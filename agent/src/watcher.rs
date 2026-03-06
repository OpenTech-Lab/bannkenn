use crate::burst::BurstDetector;
use crate::butterfly;
use crate::campaign::LocalCampaignTracker;
use crate::config::AgentConfig;
use crate::event_risk::{self, EventSurgeDetector};
use crate::geoip;
use crate::patterns::{all_patterns, all_ssh_login_patterns};
use crate::risk_level::HostRiskLevel;
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

/// A successful SSH login detected from sshd logs.
#[derive(Debug, Clone)]
struct RawSshLogin {
    ip: String,
    username: String,
    log_path: String,
}

/// A risk event generated for every matched log line.
/// `level=alert` means risky but not blocked yet.
/// `level=block` means threshold reached and block should be enforced.
/// `level=ssh_access` is an informational event: a successful SSH login was detected.
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub ip: String,
    pub reason: String,
    pub level: String,
    pub log_path: String,
    pub attempts: u32,
    pub effective_threshold: u32,
    /// Risk rank of the event type: "Low", "Medium", "High", "Critical".
    pub risk_rank: String,
    /// Set when a cross-IP campaign was detected: "volume" or "geo".
    pub campaign: Option<String>,
    /// Set for ssh_access events: the username that authenticated.
    pub username: Option<String>,
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
    let (ssh_login_tx, mut ssh_login_rx) = mpsc::channel::<RawSshLogin>(200);

    for log_path in log_paths {
        let tx_clone = raw_tx.clone();
        let ssh_tx_clone = ssh_login_tx.clone();
        tokio::spawn(async move {
            if let Err(err) = tail_log_path(log_path.clone(), tx_clone, ssh_tx_clone).await {
                tracing::error!("Tailer stopped for {}: {}", log_path, err);
            }
        });
    }
    drop(raw_tx);
    drop(ssh_login_tx); // all senders now owned by tailer tasks

    // Sliding window counters: IP -> deque of attempt timestamps
    let mut ip_attempts: HashMap<String, VecDeque<Instant>> = HashMap::new();
    // IPs already blocked — avoids re-reporting block action repeatedly.
    let mut already_blocked: HashMap<String, ()> = HashMap::new();

    let mut burst_detector = BurstDetector::new();
    let mut host_risk = HostRiskLevel::new();
    let mut surge_detector = EventSurgeDetector::new();
    let mut campaign_tracker = LocalCampaignTracker::new();

    // Spawn separate task to forward SSH login events to the main SecurityEvent channel.
    // SSH logins bypass ALL attack/threat pipeline logic and use level="ssh_access".
    let ssh_event_tx = tx.clone();
    tokio::spawn(async move {
        while let Some(login) = ssh_login_rx.recv().await {
            tracing::info!(
                "SSH access event: user={} from={} log={}",
                login.username,
                login.ip,
                login.log_path
            );
            let event = SecurityEvent {
                ip: login.ip,
                reason: "SSH successful login".to_string(),
                level: "ssh_access".to_string(),
                log_path: login.log_path,
                attempts: 1,
                effective_threshold: 1,
                risk_rank: "Low".to_string(),
                campaign: None,
                username: Some(login.username),
                timestamp: Utc::now(),
            };
            let _ = ssh_event_tx.send(event).await;
        }
    });

    while let Some(raw) = raw_rx.recv().await {
        process_failed_attempt(
            &raw,
            &mut ip_attempts,
            &mut already_blocked,
            &mut burst_detector,
            &mut host_risk,
            &mut surge_detector,
            &mut campaign_tracker,
            &config,
            &tx,
            &known_blocked_ips,
        )
        .await;
    }

    Ok(())
}

async fn tail_log_path(
    log_path: String,
    tx: mpsc::Sender<RawDetection>,
    ssh_login_tx: mpsc::Sender<RawSshLogin>,
) -> Result<()> {
    let patterns = all_patterns()?;
    let ssh_login_patterns = all_ssh_login_patterns()?;
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
                        // Unwrap Docker json-file log envelope if present so
                        // patterns match the actual log content inside it.
                        let effective_line = extract_log_line(line);

                        // Check SSH successful-login patterns first.
                        // A successful login is informational — it must NOT
                        // enter the attack pipeline.  If matched, send via the
                        // dedicated ssh_login channel and skip attack patterns.
                        let mut matched_login = false;
                        for lp in &ssh_login_patterns {
                            if let Some(caps) = lp.regex.captures(effective_line.as_ref()) {
                                if let (Some(user), Some(ip)) = (caps.get(1), caps.get(2)) {
                                    let _ = ssh_login_tx
                                        .send(RawSshLogin {
                                            ip: ip.as_str().to_string(),
                                            username: user.as_str().to_string(),
                                            log_path: log_path.clone(),
                                        })
                                        .await;
                                    matched_login = true;
                                    break;
                                }
                            }
                        }
                        if matched_login {
                            continue;
                        }

                        for pattern in &patterns {
                            if let Some(caps) = pattern.regex.captures(effective_line.as_ref()) {
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

/// Some SSH log patterns already indicate too many auth failures happened within
/// a single connection/session. Treat them as immediate block signals.
fn is_immediate_block_signal(reason: &str) -> bool {
    reason == "SSH repeated connection close"
        || reason == "SSH disconnected: too many auth failures"
        || reason == "SSH max auth attempts exceeded"
}

/// Extract the effective log content from a raw line read off disk.
///
/// When a service (nginx, sshd, any daemon) runs inside a **Docker container**
/// with the default `json-file` logging driver, Docker wraps every stdout/
/// stderr line in a JSON envelope before writing it to:
///   /var/lib/docker/containers/<id>/<id>-json.log
///
/// Each line looks like:
///   {"log":"<JSON-escaped original line>\n","stream":"stdout","time":"..."}
///
/// The agent is configured to tail that host-side path. Without this function
/// the patterns would never match because they see the JSON envelope, not the
/// actual nginx / sshd log text inside it.
///
/// For every other log format (plain text on bare-metal, VM, or bind-mounted
/// files) the function returns the line unchanged, so it is safe to call on
/// every line regardless of where the log comes from.
fn extract_log_line(line: &str) -> std::borrow::Cow<'_, str> {
    // Fast path: Docker JSON log lines always start with {"log":
    if line.starts_with(r#"{"log":"#) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(s) = val.get("log").and_then(|v| v.as_str()) {
                // Docker always appends a trailing \n inside the JSON string.
                return std::borrow::Cow::Owned(s.trim_end_matches('\n').to_string());
            }
        }
    }
    std::borrow::Cow::Borrowed(line)
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
///
/// Processing order:
/// 1. Skip IPs already blocked this session.
/// 2. IPs in the known block-list DB → emit `level=listed` immediately.
/// 3. Burst detection (if enabled) → block immediately on rapid-fire hits.
/// 4. Sliding-window attempt counter (enforces minimum 10 s window).
/// 5. Butterfly or static base threshold, reduced by host risk level.
/// 6. Event-type risk rank + surge → further reduce threshold.
/// 7. Campaign correlation (cross-IP) → if campaign, set threshold = 1.
/// 8. Immediate-block signal check (certain SSH events hard-block regardless).
/// 9. Emit alert or block event based on attempts vs effective threshold.
#[allow(clippy::too_many_arguments)]
async fn process_failed_attempt(
    raw: &RawDetection,
    ip_attempts: &mut HashMap<String, VecDeque<Instant>>,
    already_blocked: &mut HashMap<String, ()>,
    burst_detector: &mut BurstDetector,
    host_risk: &mut HostRiskLevel,
    surge_detector: &mut EventSurgeDetector,
    campaign_tracker: &mut LocalCampaignTracker,
    config: &AgentConfig,
    tx: &mpsc::Sender<SecurityEvent>,
    known_blocked_ips: &Arc<RwLock<HashMap<String, String>>>,
) {
    // Step 1: already blocked this session — skip silently.
    if already_blocked.contains_key(&raw.ip) {
        return;
    }

    // Step 2: IP is in the block list DB — emit "listed" and block immediately.
    if let Some(source) = known_blocked_ips.read().await.get(&raw.ip).cloned() {
        let display = format_source(&source);
        let event = SecurityEvent {
            ip: raw.ip.clone(),
            reason: format!("Listed in {}", display),
            level: "listed".to_string(),
            log_path: raw.log_path.clone(),
            attempts: 1,
            effective_threshold: 0,
            risk_rank: event_risk::classify_reason(&raw.reason)
                .as_str()
                .to_string(),
            campaign: None,
            username: None,
            timestamp: Utc::now(),
        };
        let _ = tx.send(event).await;
        already_blocked.insert(raw.ip.clone(), ());
        return;
    }

    // Step 3: Burst detection — block immediately if rapid-fire threshold is hit.
    if let Some(burst_cfg) = config.burst.as_ref().filter(|c| c.enabled) {
        if let Some(burst_count) = burst_detector.record(&raw.ip, &raw.reason, burst_cfg) {
            let rank = event_risk::classify_reason(&raw.reason);
            let reason = format!(
                "{} [burst: {} hits in {}s]",
                raw.reason, burst_count, burst_cfg.window_secs
            );
            let event = SecurityEvent {
                ip: raw.ip.clone(),
                reason,
                level: "block".to_string(),
                log_path: raw.log_path.clone(),
                attempts: burst_count as u32,
                effective_threshold: burst_cfg.threshold,
                risk_rank: rank.as_str().to_string(),
                campaign: None,
                username: None,
                timestamp: Utc::now(),
            };
            let _ = tx.send(event).await;

            tracing::info!(
                "Burst detected for IP {}: {} hits within {}s",
                raw.ip,
                burst_count,
                burst_cfg.window_secs
            );

            burst_detector.clear_ip(&raw.ip);
            // Also clear the sliding-window state so stale entries don't accumulate.
            ip_attempts.remove(&raw.ip);
            host_risk.record_block();
            already_blocked.insert(raw.ip.clone(), ());
            return;
        }
    }

    // Step 4: Sliding window threshold.
    //
    // Guard: treat window_secs=0 as a fatal misconfiguration rather than
    // silently evicting every entry (duration > ZERO is always true for any
    // non-zero elapsed time, so the deque would be emptied on every call,
    // keeping the count permanently at 1).
    let window_secs = config.window_secs.max(10);
    if config.window_secs < 10 {
        tracing::warn!(
            "window_secs={} is dangerously low (minimum enforced: 10s). \
             Update your config to avoid the count always being stuck at 1.",
            config.window_secs
        );
    }

    let now = Instant::now();
    let window = Duration::from_secs(window_secs);

    let attempts = ip_attempts.entry(raw.ip.clone()).or_default();

    while let Some(&oldest) = attempts.front() {
        if now.duration_since(oldest) > window {
            attempts.pop_front();
        } else {
            break;
        }
    }

    attempts.push_back(now);

    // Step 5: Compute base effective threshold (butterfly or static).
    let mut effective = match &config.butterfly_shield {
        Some(cfg) if cfg.enabled => {
            butterfly::effective_threshold(config.threshold, &raw.ip, window_secs, cfg)
        }
        _ => config.threshold,
    };

    // Step 6: Apply host risk level multiplier (if enabled).
    if let Some(risk_cfg) = config.risk_level.as_ref() {
        effective = host_risk.apply(effective, risk_cfg);
    }

    // Step 7: Event-type risk rank + surge detection.
    // The rank multiplier scales the threshold by event severity (Critical → 0.25×,
    // High → 0.5×, Medium → 0.75×, Low → 1.0×).  If the event type is currently
    // surging (frequency >> historical baseline), an additional reduction applies.
    let (effective_after_rank, rank, surge_active) =
        if let Some(er_cfg) = config.event_risk.as_ref() {
            event_risk::adjust_threshold(effective, &raw.reason, surge_detector, er_cfg)
        } else {
            // Rank is still computed for logging even when adjustment is disabled.
            (effective, event_risk::classify_reason(&raw.reason), false)
        };
    effective = effective_after_rank;

    // Step 8: GeoIP + campaign correlation.
    // Track distinct IPs per attack category (and per country+ISP when geo_grouping
    // is enabled).  When a campaign is detected, enforce threshold = 1 so the
    // very next new attacker IP is blocked immediately.
    let geo_tag = geoip::lookup(&raw.ip);
    let campaign_level = if let Some(campaign_cfg) = config.campaign.as_ref() {
        campaign_tracker.record(&raw.ip, &raw.reason, Some(&geo_tag), campaign_cfg)
    } else {
        None
    };
    if campaign_level.is_some() {
        effective = 1;
    }

    // Build tag string for reason annotation (e.g. "[High, surge, campaign:volume]").
    let mut tags: Vec<String> = Vec::new();
    if rank != event_risk::RiskRank::Low {
        tags.push(rank.as_str().to_string());
    }
    if surge_active {
        tags.push("surge".to_string());
    }
    if let Some(ref cl) = campaign_level {
        tags.push(cl.label());
    }
    let tag_str = if tags.is_empty() {
        String::new()
    } else {
        format!(" [{}]", tags.join(", "))
    };

    tracing::debug!(
        "Sliding-window count for {}: {}/{} (window={}s, rank={:?}, surge={}, campaign={})",
        raw.ip,
        attempts.len(),
        effective,
        window_secs,
        rank,
        surge_active,
        campaign_level
            .as_ref()
            .map(|c| c.as_str())
            .unwrap_or("none")
    );

    if is_immediate_block_signal(&raw.reason) {
        let reason = format!("{}{} (immediate block signal)", raw.reason, tag_str);
        let security_event = SecurityEvent {
            ip: raw.ip.clone(),
            reason,
            level: "block".to_string(),
            log_path: raw.log_path.clone(),
            attempts: attempts.len() as u32,
            effective_threshold: effective,
            risk_rank: rank.as_str().to_string(),
            campaign: campaign_level.as_ref().map(|c| c.as_str().to_string()),
            username: None,
            timestamp: Utc::now(),
        };

        let _ = tx.send(security_event).await;

        tracing::info!(
            "Immediate block signal for IP {}{}  country={} asn='{}' reason='{}'",
            raw.ip,
            tag_str,
            geo_tag.country,
            geo_tag.asn_org,
            raw.reason
        );

        host_risk.record_block();
        already_blocked.insert(raw.ip.clone(), ());
        ip_attempts.remove(&raw.ip);
        return;
    }

    let level = if attempts.len() >= effective as usize {
        "block"
    } else {
        "alert"
    };

    // Build the reason string:
    // Block: "Invalid SSH user [High, surge] (threshold: 2)"
    // Alert: "Invalid SSH user [High] (2/3)"
    let reason = if level == "block" {
        format!("{}{} (threshold: {})", raw.reason, tag_str, effective)
    } else {
        format!(
            "{}{} ({}/{})",
            raw.reason,
            tag_str,
            attempts.len(),
            effective
        )
    };

    let security_event = SecurityEvent {
        ip: raw.ip.clone(),
        reason,
        level: level.to_string(),
        log_path: raw.log_path.clone(),
        attempts: attempts.len() as u32,
        effective_threshold: effective,
        risk_rank: rank.as_str().to_string(),
        campaign: campaign_level.as_ref().map(|c| c.as_str().to_string()),
        username: None,
        timestamp: Utc::now(),
    };

    let _ = tx.send(security_event).await;

    if level == "block" {
        tracing::info!(
            "Threshold exceeded for IP {}{}  country={} asn='{}' attempts={}/{} reason='{}'",
            raw.ip,
            tag_str,
            geo_tag.country,
            geo_tag.asn_org,
            attempts.len(),
            effective,
            raw.reason
        );

        host_risk.record_block();
        already_blocked.insert(raw.ip.clone(), ());
        ip_attempts.remove(&raw.ip);
    }
}

#[cfg(test)]
mod tests {
    use super::{extract_log_line, is_immediate_block_signal};

    #[test]
    fn immediate_block_signal_matches_ssh_close_patterns() {
        assert!(is_immediate_block_signal("SSH repeated connection close"));
        assert!(is_immediate_block_signal(
            "SSH disconnected: too many auth failures"
        ));
        assert!(is_immediate_block_signal("SSH max auth attempts exceeded"));
    }

    #[test]
    fn immediate_block_signal_does_not_match_normal_alert_patterns() {
        assert!(!is_immediate_block_signal("Failed SSH password"));
        assert!(!is_immediate_block_signal("Invalid SSH user"));
        assert!(!is_immediate_block_signal("PAM authentication failure"));
    }

    // ── Docker json-file log unwrapping ──────────────────────────────────────

    #[test]
    fn extract_log_line_unwraps_docker_json_envelope() {
        // Exact format written by Docker's json-file logging driver.
        let raw = r#"{"log":"89.248.168.239 - - [05/Mar/2026:02:18:53 +0000] \"POST /wp-content/plugins/dzs-videogallery/class_parts/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1\" 444 0 \"-\" \"Mozilla/5.0\"\n","stream":"stdout","time":"2026-03-05T02:18:53.123456789Z"}"#;
        let result = extract_log_line(raw);
        assert_eq!(
            result.as_ref(),
            r#"89.248.168.239 - - [05/Mar/2026:02:18:53 +0000] "POST /wp-content/plugins/dzs-videogallery/class_parts/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1" 444 0 "-" "Mozilla/5.0""#,
            "should unescape JSON and strip trailing newline"
        );
    }

    #[test]
    fn extract_log_line_passes_through_plain_text() {
        let plain = r#"89.248.168.239 - - [05/Mar/2026:02:18:53 +0000] "GET / HTTP/1.1" 200 1024"#;
        let result = extract_log_line(plain);
        assert_eq!(
            result.as_ref(),
            plain,
            "plain lines must pass through unchanged"
        );
    }

    #[test]
    fn extract_log_line_passes_through_syslog_style() {
        let syslog =
            "Mar  5 02:18:53 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2";
        let result = extract_log_line(syslog);
        assert_eq!(result.as_ref(), syslog);
    }

    #[test]
    fn extract_log_line_unwraps_docker_stderr() {
        // stderr stream — same envelope, different stream field
        let raw = r#"{"log":"2026/03/05 02:18:53 [error] 12#0: *1 connect() failed\n","stream":"stderr","time":"2026-03-05T02:18:53.000000000Z"}"#;
        let result = extract_log_line(raw);
        assert_eq!(
            result.as_ref(),
            "2026/03/05 02:18:53 [error] 12#0: *1 connect() failed"
        );
    }
}
