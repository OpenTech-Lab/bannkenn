use crate::butterfly;
use crate::config::AgentConfig;
use crate::patterns::all_patterns;
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

/// Event indicating an IP should be blocked
#[derive(Debug, Clone)]
pub struct BlockEvent {
    pub ip: String,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

/// Monitors log file for failed login attempts and sends block events
/// when threshold is exceeded within a time window
pub async fn watch(config: Arc<AgentConfig>, tx: mpsc::Sender<BlockEvent>) -> Result<()> {
    let patterns = all_patterns()?;

    // Sliding window counters: IP -> deque of attempt timestamps
    let mut ip_attempts: HashMap<String, VecDeque<Instant>> = HashMap::new();

    // IPs already blocked — avoids re-reporting to the server on every
    // subsequent threshold crossing once a block is in effect.
    let mut already_blocked: HashSet<String> = HashSet::new();

    let mut file = open_log_at_end(&config.log_path).await?;
    let mut file_pos = file.seek(std::io::SeekFrom::Current(0)).await?;

    let mut buffer = String::new();
    let poll_interval = Duration::from_millis(200);

    loop {
        // Detect log rotation: if the file on disk is now shorter than our
        // read position the log was rotated. Reopen from the start of the
        // new file so we don't miss entries.
        if let Ok(meta) = tokio::fs::metadata(&config.log_path).await {
            if meta.len() < file_pos {
                tracing::info!("Log rotation detected, reopening {}", config.log_path);
                file = open_log_from_start(&config.log_path).await?;
                file_pos = 0;
            }
        }

        buffer.clear();
        match file.read_to_string(&mut buffer).await {
            Ok(0) => {
                sleep(poll_interval).await;
                continue;
            }
            Ok(_) => {
                file_pos = file.seek(std::io::SeekFrom::Current(0)).await?;

                for line in buffer.lines() {
                    for pattern in &patterns {
                        if let Some(caps) = pattern.regex.captures(line) {
                            if let Some(m) = caps.get(1) {
                                let ip = m.as_str().to_string();
                                process_failed_attempt(
                                    &ip,
                                    &mut ip_attempts,
                                    &mut already_blocked,
                                    &config,
                                    &tx,
                                    pattern.reason,
                                )
                                .await;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Error reading log file: {}", e);
                sleep(poll_interval).await;
            }
        }
    }
}

/// Open log file and seek to the end (normal startup — skip existing content).
async fn open_log_at_end(path: &str) -> Result<File> {
    let mut file = File::open(path).await?;
    file.seek(std::io::SeekFrom::End(0)).await?;
    Ok(file)
}

/// Open log file from the beginning (used after log rotation is detected).
async fn open_log_from_start(path: &str) -> Result<File> {
    Ok(File::open(path).await?)
}

/// Record a failed attempt and fire a BlockEvent when threshold is reached.
async fn process_failed_attempt(
    ip: &str,
    ip_attempts: &mut HashMap<String, VecDeque<Instant>>,
    already_blocked: &mut HashSet<String>,
    config: &AgentConfig,
    tx: &mpsc::Sender<BlockEvent>,
    reason: &str,
) {
    // Already blocked — firewall rule is in place, no need to re-report.
    if already_blocked.contains(ip) {
        return;
    }

    let now = Instant::now();
    let window = Duration::from_secs(config.window_secs);

    let attempts = ip_attempts.entry(ip.to_string()).or_default();

    // Prune attempts that fell outside the sliding window.
    while let Some(&oldest) = attempts.front() {
        if now.duration_since(oldest) > window {
            attempts.pop_front();
        } else {
            break;
        }
    }

    attempts.push_back(now);

    // Compute effective threshold — use chaos-based dynamic value when
    // ButterflyShield is enabled, otherwise fall back to the static base.
    let effective = match &config.butterfly_shield {
        Some(cfg) if cfg.enabled => butterfly::effective_threshold(config.threshold, ip, cfg),
        _ => config.threshold,
    };

    if attempts.len() >= effective as usize {
        tracing::info!(
            "Threshold exceeded for IP {}: {} attempts in window (effective threshold: {})",
            ip,
            attempts.len(),
            effective,
        );

        let block_event = BlockEvent {
            ip: ip.to_string(),
            reason: format!("{} (threshold: {})", reason, effective),
            timestamp: Utc::now(),
        };

        let _ = tx.send(block_event).await;

        // Mark as permanently blocked and drop the attempt history.
        already_blocked.insert(ip.to_string());
        ip_attempts.remove(ip);
    }
}
