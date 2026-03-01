use crate::butterfly;
use crate::config::AgentConfig;
use crate::patterns::all_patterns;
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{sleep, Duration};

#[derive(Debug, Clone)]
struct RawDetection {
    ip: String,
    reason: String,
    log_path: String,
}

/// A risk event generated for every matched log line.
/// `level=alert` means risky but not blocked yet.
/// `level=block` means threshold reached and block should be enforced.
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub ip: String,
    pub reason: String,
    pub level: String,
    pub log_path: String,
    pub attempts: u32,
    pub effective_threshold: u32,
    pub timestamp: DateTime<Utc>,
}

/// Monitors multiple log files, emits telemetry events for every detection,
/// and elevates to block when threshold is exceeded.
/// IPs already in `known_blocked_ips` are immediately emitted as `level=listed`.
pub async fn watch(
    config: Arc<AgentConfig>,
    tx: mpsc::Sender<SecurityEvent>,
    known_blocked_ips: Arc<RwLock<HashMap<String, String>>>,
) -> Result<()> {
    let log_paths = config.effective_log_paths();
    if log_paths.is_empty() {
        return Err(anyhow::anyhow!("No log paths configured"));
    }

    let (raw_tx, mut raw_rx) = mpsc::channel::<RawDetection>(1000);

    for log_path in log_paths {
        let tx_clone = raw_tx.clone();
        tokio::spawn(async move {
            if let Err(err) = tail_log_path(log_path.clone(), tx_clone).await {
                tracing::error!("Tailer stopped for {}: {}", log_path, err);
            }
        });
    }
    drop(raw_tx);

    // Sliding window counters: IP -> deque of attempt timestamps
    let mut ip_attempts: HashMap<String, VecDeque<Instant>> = HashMap::new();
    // IPs already blocked — avoids re-reporting block action repeatedly.
    let mut already_blocked: HashMap<String, ()> = HashMap::new();

    while let Some(raw) = raw_rx.recv().await {
        process_failed_attempt(
            &raw,
            &mut ip_attempts,
            &mut already_blocked,
            &config,
            &tx,
            &known_blocked_ips,
        )
        .await;
    }

    Ok(())
}

async fn tail_log_path(log_path: String, tx: mpsc::Sender<RawDetection>) -> Result<()> {
    let patterns = all_patterns()?;
    let poll_interval = Duration::from_millis(200);

    loop {
        let mut file = match open_log_at_end(&log_path).await {
            Ok(file) => file,
            Err(err) => {
                tracing::warn!("Failed to open {}: {}", log_path, err);
                sleep(Duration::from_secs(2)).await;
                continue;
            }
        };

        let mut file_pos = file.seek(std::io::SeekFrom::Current(0)).await?;
        let mut buffer = String::new();

        loop {
            if let Ok(meta) = tokio::fs::metadata(&log_path).await {
                if meta.len() < file_pos {
                    tracing::info!("Log rotation detected, reopening {}", log_path);
                    match open_log_from_start(&log_path).await {
                        Ok(new_file) => {
                            file = new_file;
                            file_pos = 0;
                        }
                        Err(err) => {
                            tracing::warn!("Failed to reopen {} after rotation: {}", log_path, err);
                            break;
                        }
                    }
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
                                    let _ = tx
                                        .send(RawDetection {
                                            ip: m.as_str().to_string(),
                                            reason: pattern.reason.to_string(),
                                            log_path: log_path.clone(),
                                        })
                                        .await;
                                }
                            }
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!("Error reading {}: {}", log_path, err);
                    break;
                }
            }
        }

        sleep(Duration::from_secs(1)).await;
    }
}

/// Convert an internal source identifier to a human-readable feed/database name.
fn format_source(source: &str) -> String {
    match source {
        "ipsum_feed" => "IPsum".to_string(),
        "agent" => "custom database".to_string(),
        other => other.replace('_', " "),
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

/// Record a failed attempt and emit alert/block telemetry.
/// If the IP is already in `known_blocked_ips` (block list DB), emits `level=listed`
/// and applies the block immediately without going through threshold counting.
async fn process_failed_attempt(
    raw: &RawDetection,
    ip_attempts: &mut HashMap<String, VecDeque<Instant>>,
    already_blocked: &mut HashMap<String, ()>,
    config: &AgentConfig,
    tx: &mpsc::Sender<SecurityEvent>,
    known_blocked_ips: &Arc<RwLock<HashMap<String, String>>>,
) {
    if already_blocked.contains_key(&raw.ip) {
        return;
    }

    // IP is already in the block list DB — emit "listed" (with source name) and block immediately.
    if let Some(source) = known_blocked_ips.read().await.get(&raw.ip).cloned() {
        let display = format_source(&source);
        let event = SecurityEvent {
            ip: raw.ip.clone(),
            reason: format!("Listed in {}", display),
            level: "listed".to_string(),
            log_path: raw.log_path.clone(),
            attempts: 1,
            effective_threshold: 0,
            timestamp: Utc::now(),
        };
        let _ = tx.send(event).await;
        already_blocked.insert(raw.ip.clone(), ());
        return;
    }

    let now = Instant::now();
    let window = Duration::from_secs(config.window_secs);

    let attempts = ip_attempts.entry(raw.ip.clone()).or_default();

    while let Some(&oldest) = attempts.front() {
        if now.duration_since(oldest) > window {
            attempts.pop_front();
        } else {
            break;
        }
    }

    attempts.push_back(now);

    let effective = match &config.butterfly_shield {
        Some(cfg) if cfg.enabled => butterfly::effective_threshold(config.threshold, &raw.ip, cfg),
        _ => config.threshold,
    };

    let level = if attempts.len() >= effective as usize {
        "block"
    } else {
        "alert"
    };

    let security_event = SecurityEvent {
        ip: raw.ip.clone(),
        reason: format!("{} (threshold: {})", raw.reason, effective),
        level: level.to_string(),
        log_path: raw.log_path.clone(),
        attempts: attempts.len() as u32,
        effective_threshold: effective,
        timestamp: Utc::now(),
    };

    let _ = tx.send(security_event).await;

    if level == "block" {
        tracing::info!(
            "Threshold exceeded for IP {}: {} attempts in window (effective threshold: {})",
            raw.ip,
            attempts.len(),
            effective
        );

        already_blocked.insert(raw.ip.clone(), ());
        ip_attempts.remove(&raw.ip);
    }
}
