use super::*;
use crate::reporting::{BehaviorEventUpload, ContainmentOutcomeUpload, ContainmentStatusUpload};

#[test]
fn outbox_round_trips_and_acks_items() {
    let dir = std::env::temp_dir().join(format!("bannkenn-outbox-{}", uuid::Uuid::new_v4()));
    let path = dir.join("outbox.toml");

    let mut outbox = Outbox::load(path.clone());
    assert_eq!(outbox.len(), 0);

    let first_id = outbox
        .enqueue(OutboxPayload::Telemetry {
            ip: "203.0.113.10".to_string(),
            reason: "Invalid SSH user".to_string(),
            level: "alert".to_string(),
            log_path: Some("/var/log/auth.log".to_string()),
            timestamp: Some("2026-03-11T09:00:00+00:00".to_string()),
        })
        .unwrap();
    let second_id = outbox
        .enqueue(OutboxPayload::Decision {
            ip: "203.0.113.10".to_string(),
            reason: "Invalid SSH user [High] (threshold: 1)".to_string(),
            timestamp: Some("2026-03-11T09:00:01+00:00".to_string()),
        })
        .unwrap();

    assert_eq!(first_id, 1);
    assert_eq!(second_id, 2);

    let reloaded = Outbox::load(path);
    assert_eq!(reloaded.len(), 2);
    assert_eq!(reloaded.peek().unwrap().id, first_id);

    let mut reloaded = reloaded;
    assert!(reloaded.ack(first_id).unwrap());
    assert_eq!(reloaded.len(), 1);
    assert_eq!(reloaded.peek().unwrap().id, second_id);

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn outbox_loads_legacy_items_without_timestamps() {
    let dir = std::env::temp_dir().join(format!("bannkenn-outbox-{}", uuid::Uuid::new_v4()));
    let path = dir.join("outbox.toml");

    fs::create_dir_all(&dir).unwrap();
    fs::write(
        &path,
        r#"
next_id = 3

[[items]]
id = 1
kind = "decision"
ip = "203.0.113.10"
reason = "Invalid SSH user"

[[items]]
id = 2
kind = "ssh_login"
ip = "203.0.113.20"
username = "root"
"#,
    )
    .unwrap();

    let outbox = Outbox::load(path);
    assert_eq!(outbox.len(), 2);

    match outbox.peek().unwrap().payload {
        OutboxPayload::Decision { timestamp, .. } => assert_eq!(timestamp, None),
        payload => panic!("expected decision payload, got {payload:?}"),
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn outbox_round_trips_behavior_and_containment_reports() {
    let dir = std::env::temp_dir().join(format!("bannkenn-outbox-{}", uuid::Uuid::new_v4()));
    let path = dir.join("outbox.toml");

    let mut outbox = Outbox::load(path.clone());
    outbox
        .enqueue(OutboxPayload::BehaviorEvent {
            report: Box::new(BehaviorEventUpload {
                timestamp: "2026-03-14T10:00:00+00:00".to_string(),
                source: "ebpf_ringbuf".to_string(),
                watched_root: "/srv/data".to_string(),
                pid: Some(42),
                parent_pid: Some(1),
                uid: Some(1000),
                gid: Some(1000),
                service_unit: Some("backup.service".to_string()),
                first_seen_at: Some("2026-03-14T09:50:00+00:00".to_string()),
                trust_class: Some("allowed_local_process".to_string()),
                trust_policy_name: Some("backup-window".to_string()),
                maintenance_activity: Some("trusted_maintenance".to_string()),
                package_name: Some("python3-minimal".to_string()),
                package_manager: Some("dpkg".to_string()),
                process_name: Some("python3".to_string()),
                exe_path: Some("/usr/bin/python3".to_string()),
                command_line: Some("python3 encrypt.py".to_string()),
                parent_process_name: Some("systemd".to_string()),
                parent_command_line: Some("systemd --user".to_string()),
                parent_chain: vec![crate::ebpf::events::ProcessAncestor {
                    pid: 1,
                    process_name: Some("systemd".to_string()),
                    exe_path: Some("/usr/lib/systemd/systemd".to_string()),
                    command_line: Some("systemd --user".to_string()),
                }],
                correlation_hits: 3,
                file_ops: crate::ebpf::events::FileOperationCounts {
                    modified: 5,
                    renamed: 2,
                    ..Default::default()
                },
                touched_paths: vec!["/srv/data/a.txt".to_string()],
                protected_paths_touched: vec!["/srv/data/secret.txt".to_string()],
                bytes_written: 4096,
                io_rate_bytes_per_sec: 2048,
                container_runtime: Some("docker".to_string()),
                container_id: Some("0123456789abcdef0123456789abcdef".to_string()),
                score: 61,
                reasons: vec!["rename burst".to_string()],
                level: "throttle_candidate".to_string(),
            }),
        })
        .unwrap();
    outbox
        .enqueue(OutboxPayload::ContainmentStatus {
            report: ContainmentStatusUpload {
                timestamp: "2026-03-14T10:00:05+00:00".to_string(),
                state: "throttle".to_string(),
                previous_state: Some("suspicious".to_string()),
                reason: "throttle score threshold crossed".to_string(),
                watched_root: "/srv/data".to_string(),
                pid: Some(42),
                score: 61,
                actions: vec!["ApplyIoThrottle".to_string()],
                outcomes: vec![ContainmentOutcomeUpload {
                    enforcer: "cgroup".to_string(),
                    applied: false,
                    dry_run: true,
                    detail: "dry-run".to_string(),
                }],
            },
        })
        .unwrap();

    let reloaded = Outbox::load(path);
    assert_eq!(reloaded.len(), 2);

    match reloaded.peek().unwrap().payload {
        OutboxPayload::BehaviorEvent { report } => {
            assert_eq!(report.source, "ebpf_ringbuf");
            assert_eq!(report.level, "throttle_candidate");
            assert_eq!(report.parent_process_name.as_deref(), Some("systemd"));
            assert_eq!(report.package_name.as_deref(), Some("python3-minimal"));
            assert_eq!(report.trust_policy_name.as_deref(), Some("backup-window"));
            assert_eq!(
                report.maintenance_activity.as_deref(),
                Some("trusted_maintenance")
            );
            assert_eq!(report.parent_chain.len(), 1);
        }
        payload => panic!("expected behavior event payload, got {payload:?}"),
    }

    let _ = fs::remove_dir_all(dir);
}
