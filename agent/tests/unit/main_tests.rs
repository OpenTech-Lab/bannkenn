use super::{
    apply_containment_setup, invalid_containment_paths, is_cloudflare_response,
    is_https_plain_http_mismatch_error, normalize_behavior_reason_category,
    parse_containment_path_list, BehaviorEventDeduper, Cli, Commands, ContainmentConfig,
    HttpProbeResult,
};
use crate::ebpf::events::{BehaviorEvent, BehaviorLevel, FileOperationCounts};
use chrono::Utc;
use clap::Parser;
use reqwest::StatusCode;
use std::{thread, time::Duration};

#[test]
fn plain_http_on_https_error_is_detected() {
    let err = anyhow::anyhow!(
        "error trying to connect: received corrupt message of type InvalidContentType"
    );
    assert!(is_https_plain_http_mismatch_error(&err));
}

#[test]
fn unrelated_tls_error_is_not_classified_as_plain_http_mismatch() {
    let err = anyhow::anyhow!("certificate verify failed: UnknownIssuer");
    assert!(!is_https_plain_http_mismatch_error(&err));
}

#[test]
fn connecttest_command_parses() {
    let cli = Cli::parse_from(["bannkenn-agent", "connecttest"]);
    assert!(matches!(cli.command, Some(Commands::ConnectTest)));
}

#[test]
fn update_command_parses_configure_containment_flag() {
    let cli = Cli::parse_from(["bannkenn-agent", "update", "--configure-containment"]);
    assert!(matches!(
        cli.command,
        Some(Commands::Update {
            configure_containment: true,
            ..
        })
    ));
}

#[test]
fn cloudflare_probe_is_detected() {
    let probe = HttpProbeResult {
        status: StatusCode::FORBIDDEN,
        server_header: Some("cloudflare".to_string()),
        cf_ray: Some("88e4ec9ec8c8e123-NRT".to_string()),
        content_type: Some("text/html".to_string()),
        body_preview: Some("Access denied".to_string()),
    };

    assert!(is_cloudflare_response(&probe));
}

#[test]
fn containment_path_parser_trims_and_deduplicates() {
    assert_eq!(
        parse_containment_path_list(" /srv/data , /var/www , /srv/data "),
        vec!["/srv/data".to_string(), "/var/www".to_string()]
    );
}

#[test]
fn relative_containment_paths_are_rejected() {
    assert_eq!(
        invalid_containment_paths(&[
            "/srv/data".to_string(),
            "relative/path".to_string(),
            "../tmp".to_string()
        ]),
        vec!["relative/path".to_string(), "../tmp".to_string()]
    );
}

#[test]
fn containment_setup_enables_dry_run_with_prompted_paths() {
    let mut containment = ContainmentConfig::default();
    apply_containment_setup(
        &mut containment,
        vec!["/srv/data".to_string()],
        vec!["/srv/data".to_string(), "/srv/backups".to_string()],
    );

    assert!(containment.enabled);
    assert!(containment.dry_run);
    assert_eq!(containment.watch_paths, vec!["/srv/data".to_string()]);
    assert_eq!(
        containment.protected_paths,
        vec!["/srv/data".to_string(), "/srv/backups".to_string()]
    );
}

fn behavior_event(score: u32, reasons: &[&str]) -> BehaviorEvent {
    BehaviorEvent {
        timestamp: Utc::now(),
        source: "userspace_polling".to_string(),
        watched_root: "/srv/data".to_string(),
        pid: Some(42),
        process_name: Some("python3".to_string()),
        exe_path: Some("/usr/bin/python3".to_string()),
        command_line: Some("python3 encrypt.py".to_string()),
        parent_process_name: Some("systemd".to_string()),
        parent_command_line: Some("systemd".to_string()),
        correlation_hits: 3,
        file_ops: FileOperationCounts {
            renamed: 4,
            ..Default::default()
        },
        touched_paths: vec!["/srv/data/a.txt".to_string()],
        protected_paths_touched: Vec::new(),
        bytes_written: 0,
        io_rate_bytes_per_sec: 0,
        score,
        reasons: reasons.iter().map(|reason| (*reason).to_string()).collect(),
        level: BehaviorLevel::Suspicious,
    }
}

#[test]
fn behavior_reason_normalization_collapses_variable_suffixes() {
    assert_eq!(
        normalize_behavior_reason_category("rename burst x11"),
        "rename burst"
    );
    assert_eq!(
        normalize_behavior_reason_category("write throughput 8192B/s"),
        "write throughput"
    );
}

#[test]
fn behavior_event_deduper_suppresses_duplicate_reason_categories_within_window() {
    let mut deduper = BehaviorEventDeduper::new(Duration::from_millis(50));
    let first = behavior_event(61, &["rename burst x4", "write throughput 4096B/s"]);
    let second = behavior_event(64, &["rename burst x7", "write throughput 8192B/s"]);

    assert!(deduper.should_report(&first));
    assert!(!deduper.should_report(&second));
}

#[test]
fn behavior_event_deduper_reopens_after_window_expires() {
    let mut deduper = BehaviorEventDeduper::new(Duration::from_millis(5));
    let event = behavior_event(61, &["rename burst x4"]);

    assert!(deduper.should_report(&event));
    thread::sleep(Duration::from_millis(10));
    assert!(deduper.should_report(&event));
}
