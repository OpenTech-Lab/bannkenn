use super::{
    build_log_source_plans, extract_log_line, handle_block_outcome, is_immediate_block_signal,
    next_retry_backoff, process_failed_attempt, BlockOutcome, LogSourcePlan, RateLimitedWarning,
    RawDetection, JOURNALD_AUTH_SOURCE_LABEL,
};
use crate::burst::BurstDetector;
use crate::campaign::LocalCampaignTracker;
use crate::config::AgentConfig;
use crate::event_risk::EventSurgeDetector;
use crate::risk_level::HostRiskLevel;
use crate::shared_risk::{SharedRiskCategory, SharedRiskSnapshot};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};
use tokio::time::Duration;

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

#[test]
fn rate_limited_warning_suppresses_duplicates_until_cooldown_expires() {
    let mut warning = RateLimitedWarning::new(Duration::from_secs(30));
    let start = Instant::now();

    assert_eq!(
        warning.record(start, "first warning"),
        Some("first warning".to_string())
    );
    assert_eq!(
        warning.record(start + Duration::from_secs(5), "second"),
        None
    );
    assert_eq!(
        warning.record(start + Duration::from_secs(10), "third"),
        None
    );
    assert_eq!(
        warning.record(start + Duration::from_secs(31), "after cooldown"),
        Some("after cooldown (suppressed 2 similar warning(s))".to_string())
    );
}

#[test]
fn retry_backoff_doubles_until_the_cap() {
    let mut backoff = Duration::from_secs(2);
    backoff = next_retry_backoff(backoff);
    assert_eq!(backoff, Duration::from_secs(4));
    backoff = next_retry_backoff(backoff);
    assert_eq!(backoff, Duration::from_secs(8));

    let capped = next_retry_backoff(Duration::from_secs(60));
    assert_eq!(capped, Duration::from_secs(60));
}

#[test]
fn build_log_source_plans_prefers_single_journald_auth_stream() {
    let sources = build_log_source_plans(
        vec![
            "/var/log/auth.log".to_string(),
            "/var/log/secure".to_string(),
            "/var/log/nginx/access.log".to_string(),
        ],
        true,
    );

    assert_eq!(sources.len(), 2);
    assert!(matches!(
        &sources[0],
        LogSourcePlan::JournaldAuth {
            display_path,
            fallback_path,
        } if display_path == JOURNALD_AUTH_SOURCE_LABEL && fallback_path == "/var/log/auth.log"
    ));
    assert!(matches!(
        &sources[1],
        LogSourcePlan::File { path } if path == "/var/log/nginx/access.log"
    ));
}

#[test]
fn build_log_source_plans_keeps_legacy_files_without_journald() {
    let sources = build_log_source_plans(
        vec![
            "/var/log/auth.log".to_string(),
            "/var/log/secure".to_string(),
        ],
        false,
    );

    assert_eq!(
        sources,
        vec![
            LogSourcePlan::File {
                path: "/var/log/auth.log".to_string(),
            },
            LogSourcePlan::File {
                path: "/var/log/secure".to_string(),
            },
        ]
    );
}

#[tokio::test]
async fn listed_ip_retries_after_failed_local_enforcement() {
    let config = AgentConfig::default();
    let raw = RawDetection {
        ip: "203.0.113.10".to_string(),
        reason: "Failed SSH password".to_string(),
        log_path: "/var/log/auth.log".to_string(),
    };
    let mut ip_attempts: HashMap<String, VecDeque<Instant>> = HashMap::new();
    let mut pending_local_blocks = HashSet::new();
    let mut burst_detector = BurstDetector::new();
    let mut host_risk = HostRiskLevel::new();
    let mut surge_detector = EventSurgeDetector::new();
    let mut campaign_tracker = LocalCampaignTracker::new();
    let (tx, mut rx) = mpsc::channel(8);
    let known_blocked_ips = Arc::new(RwLock::new(HashMap::from([(
        raw.ip.clone(),
        "ipsum_feed".to_string(),
    )])));
    let enforced_blocked_ips = Arc::new(RwLock::new(HashSet::new()));
    let whitelisted_ips = Arc::new(RwLock::new(HashSet::new()));
    let shared_risk_snapshot = Arc::new(RwLock::new(SharedRiskSnapshot::default()));

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

    let first = rx.recv().await.expect("first listed event");
    assert_eq!(first.level, "listed");
    assert!(pending_local_blocks.contains(&raw.ip));

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
    assert!(
        rx.try_recv().is_err(),
        "pending block should suppress duplicates"
    );

    handle_block_outcome(
        BlockOutcome::Failed(raw.ip.clone()),
        &mut pending_local_blocks,
        &mut ip_attempts,
        &mut burst_detector,
        &mut host_risk,
    );

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

    let second = rx
        .recv()
        .await
        .expect("listed event should retry after failure");
    assert_eq!(second.level, "listed");
}

#[tokio::test]
async fn threshold_block_retries_without_rebuilding_attempt_count() {
    let config = AgentConfig {
        threshold: 2,
        ..AgentConfig::default()
    };
    let raw = RawDetection {
        ip: "198.51.100.24".to_string(),
        reason: "Failed SSH password".to_string(),
        log_path: "/var/log/auth.log".to_string(),
    };
    let mut ip_attempts: HashMap<String, VecDeque<Instant>> = HashMap::new();
    let mut pending_local_blocks = HashSet::new();
    let mut burst_detector = BurstDetector::new();
    let mut host_risk = HostRiskLevel::new();
    let mut surge_detector = EventSurgeDetector::new();
    let mut campaign_tracker = LocalCampaignTracker::new();
    let (tx, mut rx) = mpsc::channel(8);
    let known_blocked_ips = Arc::new(RwLock::new(HashMap::new()));
    let enforced_blocked_ips = Arc::new(RwLock::new(HashSet::new()));
    let whitelisted_ips = Arc::new(RwLock::new(HashSet::new()));
    let shared_risk_snapshot = Arc::new(RwLock::new(SharedRiskSnapshot::default()));

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
    let first = rx.recv().await.expect("first alert event");
    assert_eq!(first.level, "alert");

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
    let second = rx.recv().await.expect("threshold block event");
    assert_eq!(second.level, "block");
    assert_eq!(second.attempts, 2);

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
    assert!(
        rx.try_recv().is_err(),
        "pending block should suppress duplicates"
    );

    handle_block_outcome(
        BlockOutcome::Failed(raw.ip.clone()),
        &mut pending_local_blocks,
        &mut ip_attempts,
        &mut burst_detector,
        &mut host_risk,
    );

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
    let third = rx
        .recv()
        .await
        .expect("failed local block should retry immediately");
    assert_eq!(third.level, "block");
    assert!(
        third.attempts >= 3,
        "attempt history should survive failed enforcement"
    );
}

#[tokio::test]
async fn shared_server_risk_can_force_more_aggressive_block() {
    let config = AgentConfig {
        threshold: 5,
        ..AgentConfig::default()
    };
    let raw = RawDetection {
        ip: "198.51.100.77".to_string(),
        reason: "Invalid SSH user".to_string(),
        log_path: "/var/log/auth.log".to_string(),
    };
    let mut ip_attempts: HashMap<String, VecDeque<Instant>> = HashMap::new();
    let mut pending_local_blocks = HashSet::new();
    let mut burst_detector = BurstDetector::new();
    let mut host_risk = HostRiskLevel::new();
    let mut surge_detector = EventSurgeDetector::new();
    let mut campaign_tracker = LocalCampaignTracker::new();
    let (tx, mut rx) = mpsc::channel(8);
    let known_blocked_ips = Arc::new(RwLock::new(HashMap::new()));
    let enforced_blocked_ips = Arc::new(RwLock::new(HashSet::new()));
    let whitelisted_ips = Arc::new(RwLock::new(HashSet::new()));
    let shared_risk_snapshot = Arc::new(RwLock::new(SharedRiskSnapshot {
        categories: vec![SharedRiskCategory {
            category: "Invalid SSH user".to_string(),
            distinct_ips: 3,
            distinct_agents: 2,
            event_count: 3,
            threshold_multiplier: 0.25,
            force_threshold: Some(1),
            label: "shared:campaign".to_string(),
        }],
        ..Default::default()
    }));

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

    let event = rx.recv().await.expect("shared risk should emit a block");
    assert_eq!(event.level, "block");
    assert_eq!(event.effective_threshold, 1);
    assert!(
        event.reason.contains("shared:campaign"),
        "event reason should include shared server tag"
    );
}

#[tokio::test]
async fn loopback_addresses_never_enter_the_block_pipeline() {
    let config = AgentConfig {
        threshold: 1,
        ..AgentConfig::default()
    };
    let raw = RawDetection {
        ip: "127.0.0.1".to_string(),
        reason: "Failed SSH password".to_string(),
        log_path: "/var/log/auth.log".to_string(),
    };
    let mut ip_attempts: HashMap<String, VecDeque<Instant>> = HashMap::new();
    let mut pending_local_blocks = HashSet::new();
    let mut burst_detector = BurstDetector::new();
    let mut host_risk = HostRiskLevel::new();
    let mut surge_detector = EventSurgeDetector::new();
    let mut campaign_tracker = LocalCampaignTracker::new();
    let (tx, mut rx) = mpsc::channel(8);
    let known_blocked_ips = Arc::new(RwLock::new(HashMap::new()));
    let enforced_blocked_ips = Arc::new(RwLock::new(HashSet::new()));
    let whitelisted_ips = Arc::new(RwLock::new(HashSet::new()));
    let shared_risk_snapshot = Arc::new(RwLock::new(SharedRiskSnapshot::default()));

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

    assert!(
        rx.try_recv().is_err(),
        "loopback detections should not emit alert/block events"
    );
    assert!(
        !pending_local_blocks.contains(&raw.ip),
        "loopback detections should never enter pending enforcement"
    );
    assert!(
        !ip_attempts.contains_key(&raw.ip),
        "loopback detections should not create sliding-window state"
    );
}

#[tokio::test]
async fn whitelisted_addresses_never_enter_the_block_pipeline() {
    let config = AgentConfig {
        threshold: 1,
        ..AgentConfig::default()
    };
    let raw = RawDetection {
        ip: "198.51.100.88".to_string(),
        reason: "Failed SSH password".to_string(),
        log_path: "/var/log/auth.log".to_string(),
    };
    let mut ip_attempts: HashMap<String, VecDeque<Instant>> = HashMap::new();
    let mut pending_local_blocks = HashSet::new();
    let mut burst_detector = BurstDetector::new();
    let mut host_risk = HostRiskLevel::new();
    let mut surge_detector = EventSurgeDetector::new();
    let mut campaign_tracker = LocalCampaignTracker::new();
    let (tx, mut rx) = mpsc::channel(8);
    let known_blocked_ips = Arc::new(RwLock::new(HashMap::new()));
    let enforced_blocked_ips = Arc::new(RwLock::new(HashSet::new()));
    let whitelisted_ips = Arc::new(RwLock::new(HashSet::from([raw.ip.clone()])));
    let shared_risk_snapshot = Arc::new(RwLock::new(SharedRiskSnapshot::default()));

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

    assert!(rx.try_recv().is_err());
    assert!(!pending_local_blocks.contains(&raw.ip));
    assert!(!ip_attempts.contains_key(&raw.ip));
}

#[tokio::test]
async fn cidr_whitelisted_addresses_never_enter_the_block_pipeline() {
    let config = AgentConfig {
        threshold: 1,
        ..AgentConfig::default()
    };
    let raw = RawDetection {
        ip: "203.0.113.88".to_string(),
        reason: "Failed SSH password".to_string(),
        log_path: "/var/log/auth.log".to_string(),
    };
    let mut ip_attempts: HashMap<String, VecDeque<Instant>> = HashMap::new();
    let mut pending_local_blocks = HashSet::new();
    let mut burst_detector = BurstDetector::new();
    let mut host_risk = HostRiskLevel::new();
    let mut surge_detector = EventSurgeDetector::new();
    let mut campaign_tracker = LocalCampaignTracker::new();
    let (tx, mut rx) = mpsc::channel(8);
    let known_blocked_ips = Arc::new(RwLock::new(HashMap::new()));
    let enforced_blocked_ips = Arc::new(RwLock::new(HashSet::new()));
    let whitelisted_ips = Arc::new(RwLock::new(HashSet::from(["203.0.113.0/24".to_string()])));
    let shared_risk_snapshot = Arc::new(RwLock::new(SharedRiskSnapshot::default()));

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

    assert!(rx.try_recv().is_err());
    assert!(!pending_local_blocks.contains(&raw.ip));
    assert!(!ip_attempts.contains_key(&raw.ip));
}
