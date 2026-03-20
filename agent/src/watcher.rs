use crate::burst::BurstDetector;
use crate::butterfly;
use crate::campaign::LocalCampaignTracker;
use crate::config::AgentConfig;
use crate::event_risk::{self, EventSurgeDetector};
use crate::firewall::{
    find_matching_block_source, is_block_pattern_effectively_enforced, pattern_set_matches_ip,
    should_skip_local_firewall_enforcement,
};
use crate::geoip;
use crate::patterns::{all_patterns, all_ssh_login_patterns, DetectionPattern, SshLoginPattern};
use crate::risk_level::HostRiskLevel;
use crate::shared_risk::SharedRiskSnapshot;
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Instant;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{sleep, Duration};

const TAIL_POLL_INTERVAL_MS: u64 = 200;
const TAIL_ROTATION_CHECK_IDLE_POLLS: u32 = 5;
const LOG_OPEN_INITIAL_BACKOFF_SECS: u64 = 2;
const LOG_OPEN_MAX_BACKOFF_SECS: u64 = 60;
const LOG_WARNING_COOLDOWN_SECS: u64 = 60;
const JOURNALD_AUTH_SOURCE_LABEL: &str = "journald:auth";
const JOURNALCTL_AUTH_FOLLOW_ARGS: &[&str] = &[
    "--follow",
    "--no-pager",
    "--quiet",
    "--output",
    "cat",
    "--lines",
    "0",
    "--facility=auth,authpriv",
];

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

#[derive(Debug, Clone)]
struct RateLimitedWarning {
    cooldown: Duration,
    last_emitted: Option<Instant>,
    suppressed: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LogSourcePlan {
    File {
        path: String,
    },
    JournaldAuth {
        display_path: String,
        fallback_path: String,
    },
}

impl LogSourcePlan {
    fn display_path(&self) -> &str {
        match self {
            Self::File { path } => path,
            Self::JournaldAuth { display_path, .. } => display_path,
        }
    }
}

impl RateLimitedWarning {
    fn new(cooldown: Duration) -> Self {
        Self {
            cooldown,
            last_emitted: None,
            suppressed: 0,
        }
    }

    fn record(&mut self, now: Instant, message: impl Into<String>) -> Option<String> {
        if let Some(last_emitted) = self.last_emitted {
            if now.duration_since(last_emitted) < self.cooldown {
                self.suppressed = self.suppressed.saturating_add(1);
                return None;
            }
        }

        let message = message.into();
        let rendered = if self.suppressed == 0 {
            message
        } else {
            format!(
                "{} (suppressed {} similar warning(s))",
                message, self.suppressed
            )
        };
        self.last_emitted = Some(now);
        self.suppressed = 0;
        Some(rendered)
    }

    fn reset(&mut self) {
        self.last_emitted = None;
        self.suppressed = 0;
    }
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

/// Result of a local firewall enforcement attempt.
#[derive(Debug, Clone)]
pub enum BlockOutcome {
    Enforced(String),
    Failed(String),
}

/// Monitors multiple log files, emits telemetry events for every detection,
/// and elevates to block when threshold is exceeded.
/// IPs already in `known_blocked_ips` are immediately emitted as `level=listed`.
pub async fn watch(
    config: Arc<AgentConfig>,
    tx: mpsc::Sender<SecurityEvent>,
    known_blocked_ips: Arc<RwLock<HashMap<String, String>>>,
    enforced_blocked_ips: Arc<RwLock<HashSet<String>>>,
    whitelisted_ips: Arc<RwLock<HashSet<String>>>,
    shared_risk_snapshot: Arc<RwLock<SharedRiskSnapshot>>,
    mut block_outcomes_rx: mpsc::Receiver<BlockOutcome>,
) -> Result<()> {
    let log_sources = build_log_source_plans(config.effective_log_paths(), journald_is_available());
    if log_sources.is_empty() {
        return Err(anyhow::anyhow!("No log paths configured"));
    }

    let (raw_tx, mut raw_rx) = mpsc::channel::<RawDetection>(1000);
    let (ssh_login_tx, mut ssh_login_rx) = mpsc::channel::<RawSshLogin>(200);

    for log_source in log_sources {
        let tx_clone = raw_tx.clone();
        let ssh_tx_clone = ssh_login_tx.clone();
        let display_path = log_source.display_path().to_string();
        tokio::spawn(async move {
            if let Err(err) = tail_log_source(log_source, tx_clone, ssh_tx_clone).await {
                tracing::error!("Tailer stopped for {}: {}", display_path, err);
            }
        });
    }
    drop(raw_tx);
    drop(ssh_login_tx); // all senders now owned by tailer tasks

    // Sliding window counters: IP -> deque of attempt timestamps
    let mut ip_attempts: HashMap<String, VecDeque<Instant>> = HashMap::new();
    // IPs currently waiting on a local firewall result. Suppresses duplicate
    // block/listed events while `block_ip()` is in-flight.
    let mut pending_local_blocks: HashSet<String> = HashSet::new();

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

    let mut block_outcomes_open = true;
    loop {
        tokio::select! {
            maybe_outcome = block_outcomes_rx.recv(), if block_outcomes_open => {
                match maybe_outcome {
                    Some(outcome) => {
                        handle_block_outcome(
                            outcome,
                            &mut pending_local_blocks,
                            &mut ip_attempts,
                            &mut burst_detector,
                            &mut host_risk,
                        );
                    }
                    None => block_outcomes_open = false,
                }
            }
            maybe_raw = raw_rx.recv() => {
                match maybe_raw {
                    Some(raw) => {
                        process_failed_attempt(
                            &raw,
                            &mut ip_attempts,
                            &mut pending_local_blocks,
                            &mut burst_detector,
                            &mut host_risk,
                            &mut surge_detector,
                            &mut campaign_tracker,
                            &config,
                            &tx,
                            &known_blocked_ips,
                            &enforced_blocked_ips,
                            &whitelisted_ips,
                            &shared_risk_snapshot,
                        )
                        .await;
                    }
                    None => break,
                }
            }
        }
    }

    Ok(())
}

fn build_log_source_plans(log_paths: Vec<String>, journald_available: bool) -> Vec<LogSourcePlan> {
    let mut sources = Vec::new();
    let mut journald_auth_added = false;

    for path in log_paths {
        if journald_available && is_legacy_auth_log_path(&path) {
            if !journald_auth_added {
                sources.push(LogSourcePlan::JournaldAuth {
                    display_path: JOURNALD_AUTH_SOURCE_LABEL.to_string(),
                    fallback_path: path,
                });
                journald_auth_added = true;
            }
            continue;
        }

        sources.push(LogSourcePlan::File { path });
    }

    sources
}

async fn tail_log_source(
    source: LogSourcePlan,
    tx: mpsc::Sender<RawDetection>,
    ssh_login_tx: mpsc::Sender<RawSshLogin>,
) -> Result<()> {
    match source {
        LogSourcePlan::File { path } => tail_log_path(path, tx, ssh_login_tx).await,
        LogSourcePlan::JournaldAuth {
            display_path,
            fallback_path,
        } => match tail_auth_journald(display_path.clone(), tx.clone(), ssh_login_tx.clone()).await
        {
            Ok(()) => Ok(()),
            Err(err) => {
                tracing::warn!(
                    "Failed to start {} stream: {}. Falling back to {}",
                    display_path,
                    err,
                    fallback_path
                );
                tail_log_path(fallback_path, tx, ssh_login_tx).await
            }
        },
    }
}

async fn tail_log_path(
    log_path: String,
    tx: mpsc::Sender<RawDetection>,
    ssh_login_tx: mpsc::Sender<RawSshLogin>,
) -> Result<()> {
    let patterns = all_patterns()?;
    let ssh_login_patterns = all_ssh_login_patterns()?;
    let poll_interval = Duration::from_millis(TAIL_POLL_INTERVAL_MS);
    let warning_cooldown = Duration::from_secs(LOG_WARNING_COOLDOWN_SECS);
    let mut open_warning = RateLimitedWarning::new(warning_cooldown);
    let mut read_warning = RateLimitedWarning::new(warning_cooldown);
    let mut reopen_warning = RateLimitedWarning::new(warning_cooldown);
    let mut open_backoff = Duration::from_secs(LOG_OPEN_INITIAL_BACKOFF_SECS);

    loop {
        let mut file = match open_log_at_end(&log_path).await {
            Ok(file) => {
                open_warning.reset();
                read_warning.reset();
                reopen_warning.reset();
                open_backoff = Duration::from_secs(LOG_OPEN_INITIAL_BACKOFF_SECS);
                file
            }
            Err(err) => {
                let message = missing_log_warning_message(&log_path, &err, open_backoff);
                emit_rate_limited_warning(&mut open_warning, message);
                sleep(open_backoff).await;
                open_backoff = next_retry_backoff(open_backoff);
                continue;
            }
        };

        let mut file_pos = file.seek(std::io::SeekFrom::Current(0)).await?;
        let mut buffer = String::new();
        let mut idle_polls = 0u32;

        loop {
            if idle_polls.is_multiple_of(TAIL_ROTATION_CHECK_IDLE_POLLS) {
                if let Ok(meta) = tokio::fs::metadata(&log_path).await {
                    if meta.len() < file_pos {
                        tracing::info!("Log rotation detected, reopening {}", log_path);
                        match open_log_from_start(&log_path).await {
                            Ok(new_file) => {
                                file = new_file;
                                file_pos = 0;
                                reopen_warning.reset();
                                idle_polls = 0;
                            }
                            Err(err) => {
                                emit_rate_limited_warning(
                                    &mut reopen_warning,
                                    format!(
                                        "Failed to reopen {} after rotation: {}",
                                        log_path, err
                                    ),
                                );
                                break;
                            }
                        }
                    }
                }
            }

            buffer.clear();
            match file.read_to_string(&mut buffer).await {
                Ok(0) => {
                    idle_polls = idle_polls.saturating_add(1);
                    sleep(poll_interval).await;
                    continue;
                }
                Ok(_) => {
                    idle_polls = 0;
                    file_pos = file.seek(std::io::SeekFrom::Current(0)).await?;

                    for line in buffer.lines() {
                        dispatch_log_line(
                            line,
                            &log_path,
                            &patterns,
                            &ssh_login_patterns,
                            &tx,
                            &ssh_login_tx,
                        )
                        .await;
                    }
                }
                Err(err) => {
                    emit_rate_limited_warning(
                        &mut read_warning,
                        format!("Error reading {}: {}", log_path, err),
                    );
                    break;
                }
            }
        }

        sleep(open_backoff).await;
        open_backoff = next_retry_backoff(open_backoff);
    }
}

async fn tail_auth_journald(
    display_path: String,
    tx: mpsc::Sender<RawDetection>,
    ssh_login_tx: mpsc::Sender<RawSshLogin>,
) -> Result<()> {
    let patterns = all_patterns()?;
    let ssh_login_patterns = all_ssh_login_patterns()?;
    let warning_cooldown = Duration::from_secs(LOG_WARNING_COOLDOWN_SECS);
    let mut stream_warning = RateLimitedWarning::new(warning_cooldown);
    let mut restart_backoff = Duration::from_secs(LOG_OPEN_INITIAL_BACKOFF_SECS);
    let mut started_once = false;

    loop {
        let mut child = match spawn_auth_journalctl_follow() {
            Ok(child) => {
                if !started_once {
                    tracing::info!(
                        "Using journald auth stream {} instead of legacy auth file polling",
                        display_path
                    );
                }
                started_once = true;
                stream_warning.reset();
                restart_backoff = Duration::from_secs(LOG_OPEN_INITIAL_BACKOFF_SECS);
                child
            }
            Err(err) if !started_once => return Err(err),
            Err(err) => {
                emit_rate_limited_warning(
                    &mut stream_warning,
                    format!(
                        "Failed to restart {} stream: {}. Retrying in {}s",
                        display_path,
                        err,
                        restart_backoff.as_secs().max(1)
                    ),
                );
                sleep(restart_backoff).await;
                restart_backoff = next_retry_backoff(restart_backoff);
                continue;
            }
        };

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("journalctl follow did not expose stdout"))?;
        let mut lines = BufReader::new(stdout).lines();

        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    dispatch_log_line(
                        &line,
                        &display_path,
                        &patterns,
                        &ssh_login_patterns,
                        &tx,
                        &ssh_login_tx,
                    )
                    .await;
                }
                Ok(None) => {
                    let status = child.wait().await?;
                    emit_rate_limited_warning(
                        &mut stream_warning,
                        format!(
                            "{} stream exited with status {}. Restarting in {}s",
                            display_path,
                            status,
                            restart_backoff.as_secs().max(1)
                        ),
                    );
                    break;
                }
                Err(err) => {
                    emit_rate_limited_warning(
                        &mut stream_warning,
                        format!(
                            "Error reading {} stream: {}. Restarting in {}s",
                            display_path,
                            err,
                            restart_backoff.as_secs().max(1)
                        ),
                    );
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    break;
                }
            }
        }

        sleep(restart_backoff).await;
        restart_backoff = next_retry_backoff(restart_backoff);
    }
}

fn spawn_auth_journalctl_follow() -> Result<tokio::process::Child> {
    let mut command = Command::new("journalctl");
    command
        .args(JOURNALCTL_AUTH_FOLLOW_ARGS)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null())
        .kill_on_drop(true);
    Ok(command.spawn()?)
}

async fn dispatch_log_line(
    line: &str,
    log_path: &str,
    patterns: &[DetectionPattern],
    ssh_login_patterns: &[SshLoginPattern],
    tx: &mpsc::Sender<RawDetection>,
    ssh_login_tx: &mpsc::Sender<RawSshLogin>,
) {
    let effective_line = extract_log_line(line);

    for login_pattern in ssh_login_patterns {
        if let Some(caps) = login_pattern.regex.captures(effective_line.as_ref()) {
            if let (Some(user), Some(ip)) = (caps.get(1), caps.get(2)) {
                let _ = ssh_login_tx
                    .send(RawSshLogin {
                        ip: ip.as_str().to_string(),
                        username: user.as_str().to_string(),
                        log_path: log_path.to_string(),
                    })
                    .await;
                return;
            }
        }
    }

    for pattern in patterns {
        if let Some(caps) = pattern.regex.captures(effective_line.as_ref()) {
            if let Some(m) = caps.get(1) {
                let _ = tx
                    .send(RawDetection {
                        ip: m.as_str().to_string(),
                        reason: pattern.reason.to_string(),
                        log_path: log_path.to_string(),
                    })
                    .await;
            }
        }
    }
}

fn emit_rate_limited_warning(limiter: &mut RateLimitedWarning, message: String) {
    if let Some(rendered) = limiter.record(Instant::now(), message) {
        tracing::warn!("{}", rendered);
    }
}

fn missing_log_warning_message(
    log_path: &str,
    error: &anyhow::Error,
    retry_delay: Duration,
) -> String {
    let retry_secs = retry_delay.as_secs().max(1);
    if should_hint_journald(log_path, error) {
        format!(
            "Failed to open {}: {}. journald appears to be available, so file polling will back off for {}s until the path exists",
            log_path, error, retry_secs
        )
    } else {
        format!(
            "Failed to open {}: {}. Backing off file polling for {}s",
            log_path, error, retry_secs
        )
    }
}

fn should_hint_journald(log_path: &str, error: &anyhow::Error) -> bool {
    matches!(
        error
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind),
        Some(std::io::ErrorKind::NotFound)
    ) && is_legacy_auth_log_path(log_path)
        && journald_is_available()
}

fn is_legacy_auth_log_path(log_path: &str) -> bool {
    matches!(
        log_path,
        "/var/log/auth.log" | "/var/log/secure" | "/var/log/syslog" | "/var/log/messages"
    )
}

fn journald_is_available() -> bool {
    Path::new("/run/systemd/journal/socket").exists() || Path::new("/var/log/journal").is_dir()
}

fn next_retry_backoff(current: Duration) -> Duration {
    let current_secs = current.as_secs().max(1);
    Duration::from_secs(
        current_secs
            .saturating_mul(2)
            .min(LOG_OPEN_MAX_BACKOFF_SECS),
    )
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

fn handle_block_outcome(
    outcome: BlockOutcome,
    pending_local_blocks: &mut HashSet<String>,
    ip_attempts: &mut HashMap<String, VecDeque<Instant>>,
    burst_detector: &mut BurstDetector,
    host_risk: &mut HostRiskLevel,
) {
    match outcome {
        BlockOutcome::Enforced(ip) => {
            pending_local_blocks.remove(&ip);
            ip_attempts.remove(&ip);
            burst_detector.clear_ip(&ip);
            host_risk.record_block();
        }
        BlockOutcome::Failed(ip) => {
            pending_local_blocks.remove(&ip);
        }
    }
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
/// 0. Skip local/self-originated addresses that should never hit the firewall.
/// 1. Skip IPs already locally enforced or currently pending enforcement.
/// 2. IPs in the known block-list DB → emit `level=listed` immediately.
/// 3. Burst detection (if enabled) → block immediately on rapid-fire hits.
/// 4. Sliding-window attempt counter (enforces minimum 10 s window).
/// 5. Butterfly or static base threshold.
/// 6. Host risk level adjustment.
/// 7. Event-type risk rank + surge → further reduce threshold.
/// 8. Campaign correlation (cross-IP) → if campaign, set threshold = 1.
/// 9. Merge server-shared risk profile and choose the more aggressive threshold.
/// 10. Immediate-block signal check (certain SSH events hard-block regardless).
/// 11. Emit alert or block event based on attempts vs effective threshold.
#[allow(clippy::too_many_arguments)]
async fn process_failed_attempt(
    raw: &RawDetection,
    ip_attempts: &mut HashMap<String, VecDeque<Instant>>,
    pending_local_blocks: &mut HashSet<String>,
    burst_detector: &mut BurstDetector,
    host_risk: &mut HostRiskLevel,
    surge_detector: &mut EventSurgeDetector,
    campaign_tracker: &mut LocalCampaignTracker,
    config: &AgentConfig,
    tx: &mpsc::Sender<SecurityEvent>,
    known_blocked_ips: &Arc<RwLock<HashMap<String, String>>>,
    enforced_blocked_ips: &Arc<RwLock<HashSet<String>>>,
    whitelisted_ips: &Arc<RwLock<HashSet<String>>>,
    shared_risk_snapshot: &Arc<RwLock<SharedRiskSnapshot>>,
) {
    if should_skip_local_firewall_enforcement(&raw.ip) {
        tracing::debug!(
            "Ignoring local/reserved source address {}; skipping detection pipeline",
            raw.ip
        );
        return;
    }

    let is_whitelisted = {
        let whitelist = whitelisted_ips.read().await;
        pattern_set_matches_ip(&whitelist, &raw.ip)
    };
    if is_whitelisted {
        tracing::debug!("Ignoring whitelisted source address {}", raw.ip);
        return;
    }

    // Step 1: local firewall already enforced this IP, or an enforcement attempt
    // is still in-flight — skip silently.
    let is_enforced = {
        let enforced = enforced_blocked_ips.read().await;
        is_block_pattern_effectively_enforced(&raw.ip, &enforced)
    };
    if pending_local_blocks.contains(&raw.ip) || is_enforced {
        return;
    }

    // Step 2: IP is in the block list DB — emit "listed" and block immediately.
    let listed_source = {
        let known = known_blocked_ips.read().await;
        find_matching_block_source(&known, &raw.ip)
    };
    if let Some(source) = listed_source {
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
        pending_local_blocks.insert(raw.ip.clone());
        if tx.send(event).await.is_err() {
            pending_local_blocks.remove(&raw.ip);
        }
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
            pending_local_blocks.insert(raw.ip.clone());
            if tx.send(event).await.is_err() {
                pending_local_blocks.remove(&raw.ip);
            }

            tracing::info!(
                "Burst detected for IP {}: {} hits within {}s",
                raw.ip,
                burst_count,
                burst_cfg.window_secs
            );
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
    let base_effective = match &config.butterfly_shield {
        Some(cfg) if cfg.enabled => {
            butterfly::effective_threshold(config.threshold, &raw.ip, window_secs, cfg)
        }
        _ => config.threshold,
    };
    let mut effective = base_effective;

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

    let shared_decision = shared_risk_snapshot
        .read()
        .await
        .apply(base_effective, &raw.reason);
    let shared_tags = if let Some(shared_effective) = shared_decision.effective_threshold {
        if shared_effective <= effective {
            effective = shared_effective;
            shared_decision.tags
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

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
    tags.extend(shared_tags);
    let tag_str = if tags.is_empty() {
        String::new()
    } else {
        tags.sort();
        tags.dedup();
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

        pending_local_blocks.insert(raw.ip.clone());
        if tx.send(security_event).await.is_err() {
            pending_local_blocks.remove(&raw.ip);
        }

        tracing::info!(
            "Immediate block signal for IP {}{}  country={} asn='{}' reason='{}'",
            raw.ip,
            tag_str,
            geo_tag.country,
            geo_tag.asn_org,
            raw.reason
        );
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

    if level == "block" {
        pending_local_blocks.insert(raw.ip.clone());
    }

    if tx.send(security_event).await.is_err() && level == "block" {
        pending_local_blocks.remove(&raw.ip);
    }

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
    }
}

#[cfg(test)]
#[path = "../tests/unit/watcher_tests.rs"]
mod tests;
