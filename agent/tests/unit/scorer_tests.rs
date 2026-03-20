use super::*;
use crate::config::ContainmentConfig;
use crate::ebpf::events::{
    FileActivityBatch, FileOperationCounts, MaintenanceActivity, ProcessAncestor, ProcessInfo,
    ProcessTrustClass,
};
use crate::shared_risk::{SharedProcessProfile, SharedRiskSnapshot};
use chrono::Utc;

fn batch_with_ops(
    file_ops: FileOperationCounts,
    touched_paths: Vec<&str>,
    bytes_written: u64,
) -> FileActivityBatch {
    FileActivityBatch {
        timestamp: Utc::now(),
        source: "userspace_polling".to_string(),
        watched_root: "/tmp".to_string(),
        poll_interval_ms: 1000,
        file_ops,
        touched_paths: touched_paths.into_iter().map(str::to_string).collect(),
        protected_paths_touched: Vec::new(),
        rename_extension_targets: Vec::new(),
        content_indicators: Default::default(),
        bytes_written,
        io_rate_bytes_per_sec: bytes_written,
    }
}

fn process(pid: u32, process_name: &str, exe_path: &str, command_line: &str) -> ProcessInfo {
    ProcessInfo {
        pid,
        parent_pid: None,
        uid: None,
        gid: None,
        service_unit: None,
        first_seen_at: Utc::now(),
        trust_class: ProcessTrustClass::Unknown,
        trust_policy_name: None,
        maintenance_activity: None,
        trust_policy_visibility: Default::default(),
        package_name: None,
        package_manager: None,
        process_name: process_name.to_string(),
        exe_path: exe_path.to_string(),
        command_line: command_line.to_string(),
        correlation_hits: 20,
        parent_process_name: None,
        parent_command_line: None,
        parent_chain: Vec::new(),
        container_runtime: None,
        container_id: None,
        container_image: None,
        orchestrator: Default::default(),
        container_mounts: Vec::new(),
    }
}

#[test]
fn mass_rename_scores_as_suspicious() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let batch = FileActivityBatch {
        timestamp: Utc::now(),
        source: "userspace_polling".to_string(),
        watched_root: "/srv/data".to_string(),
        poll_interval_ms: 1000,
        file_ops: FileOperationCounts {
            renamed: 11,
            ..Default::default()
        },
        touched_paths: vec!["/srv/data/a".to_string()],
        protected_paths_touched: Vec::new(),
        rename_extension_targets: Vec::new(),
        content_indicators: Default::default(),
        bytes_written: 0,
        io_rate_bytes_per_sec: 0,
    };
    let correlation = CorrelationResult {
        process: Some(ProcessInfo {
            pid: 4242,
            parent_pid: Some(1),
            uid: Some(1000),
            gid: Some(1000),
            service_unit: Some("backup.service".to_string()),
            first_seen_at: Utc::now(),
            trust_class: ProcessTrustClass::AllowedLocal,
            trust_policy_name: None,
            maintenance_activity: None,
            trust_policy_visibility: Default::default(),
            package_name: None,
            package_manager: None,
            process_name: "python3".to_string(),
            exe_path: "/usr/bin/python3".to_string(),
            command_line: "python3 encrypt.py".to_string(),
            correlation_hits: 20,
            parent_process_name: Some("systemd".to_string()),
            parent_command_line: Some("systemd".to_string()),
            parent_chain: Vec::new(),
            container_runtime: None,
            container_id: None,
            container_image: None,
            orchestrator: Default::default(),
            container_mounts: Vec::new(),
        }),
        protected_hits: 0,
    };

    let event = scorer.score(&batch, &correlation);
    assert_eq!(
        event.level,
        BehaviorLevel::Suspicious,
        "score={} reasons={:?}",
        event.score,
        event.reasons
    );
    assert!(event.score > 30);
}

#[test]
fn fleet_shared_process_profile_downgrades_unknown_managed_lineage() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let batch = FileActivityBatch {
        timestamp: Utc::now(),
        source: "aya_ringbuf".to_string(),
        watched_root: "/srv/data".to_string(),
        poll_interval_ms: 1000,
        file_ops: FileOperationCounts {
            modified: 6,
            ..Default::default()
        },
        touched_paths: vec!["/srv/data/db.sqlite".to_string()],
        protected_paths_touched: Vec::new(),
        rename_extension_targets: Vec::new(),
        content_indicators: Default::default(),
        bytes_written: 0,
        io_rate_bytes_per_sec: 0,
    };
    let correlation = CorrelationResult {
        process: Some({
            let mut proc = process(
                4243,
                "python3",
                "/usr/bin/python3",
                "python3 /opt/backup/runner.py --sync",
            );
            proc.service_unit = Some("backup.service".to_string());
            proc.package_name = Some("python3".to_string());
            proc.container_image = Some("ghcr.io/acme/backup:1.2.3".to_string());
            proc.parent_process_name = Some("systemd".to_string());
            proc.parent_command_line = Some("systemd".to_string());
            proc
        }),
        protected_hits: 0,
    };
    let shared_risk = SharedRiskSnapshot {
        process_profiles: vec![SharedProcessProfile {
            identity: "/usr/bin/python3|backup.service|python3|ghcr.io/acme/backup:1.2.3"
                .to_string(),
            exe_path: "/usr/bin/python3".to_string(),
            service_unit: Some("backup.service".to_string()),
            package_name: Some("python3".to_string()),
            container_image: Some("ghcr.io/acme/backup:1.2.3".to_string()),
            trust_class: "trusted_package_managed_process".to_string(),
            distinct_agents: 3,
            event_count: 7,
            highest_level: "observed".to_string(),
            label: "shared:trusted-package".to_string(),
        }],
        ..Default::default()
    };

    let baseline_event = scorer.score(&batch, &correlation);
    let shared_event = scorer.score_with_shared_risk(&batch, &correlation, &shared_risk);

    assert_eq!(baseline_event.level, BehaviorLevel::Suspicious);
    assert_eq!(shared_event.level, BehaviorLevel::Observed);
    assert!(shared_event.score < baseline_event.score);
    assert!(shared_event
        .reasons
        .iter()
        .any(|reason| reason == "fleet-shared trusted package lineage (shared:trusted-package)"));
}

#[test]
fn small_rename_burst_stays_observed() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let batch = batch_with_ops(
        FileOperationCounts {
            renamed: 3,
            ..Default::default()
        },
        vec!["/srv/data/report.docx"],
        0,
    );
    let correlation = CorrelationResult {
        process: Some(process(
            77,
            "python3",
            "/usr/bin/python3",
            "python3 rename.py /srv/data",
        )),
        protected_hits: 0,
    };

    let event = scorer.score(&batch, &correlation);

    assert_eq!(event.level, BehaviorLevel::Observed);
    assert_eq!(event.score, 0);
    assert!(event
        .reasons
        .iter()
        .any(|reason| reason == "rename burst x3"));
}

#[test]
fn unknown_process_write_only_no_longer_crosses_suspicious_threshold_by_itself() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let batch = batch_with_ops(
        FileOperationCounts {
            modified: 8,
            ..Default::default()
        },
        vec!["/tmp/write-only.tmp"],
        0,
    );
    let correlation = CorrelationResult::default();

    let event = scorer.score(&batch, &correlation);

    assert_eq!(event.level, BehaviorLevel::Observed);
    assert!(!event
        .reasons
        .iter()
        .any(|reason| reason == "unknown process activity"));
}

#[test]
fn known_java_temp_extraction_is_downgraded() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let batch = batch_with_ops(
        FileOperationCounts {
            modified: 5,
            deleted: 5,
            ..Default::default()
        },
        vec!["/tmp/opensearch-123/libzstd-jni.so"],
        2 * 1_048_576,
    );
    let correlation = CorrelationResult {
        process: Some(process(
            4242,
            "java",
            "/usr/share/wazuh-indexer/jdk/bin/java",
            "/usr/share/wazuh-indexer/jdk/bin/java -Djava.io.tmpdir=/tmp/opensearch-123 -cp /usr/share/wazuh-indexer/lib/* org.opensearch.bootstrap.OpenSearch",
        )),
        protected_hits: 0,
    };

    let event = scorer.score(&batch, &correlation);

    assert_eq!(event.level, BehaviorLevel::Observed);
    assert!(event
        .reasons
        .iter()
        .any(|reason| reason == "known JVM temp extraction pattern"));
}

#[test]
fn package_manager_helper_temp_activity_is_downgraded() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let batch = batch_with_ops(
        FileOperationCounts {
            modified: 10,
            ..Default::default()
        },
        vec!["/var/tmp/dpkg-unpack"],
        3 * 1_048_576,
    );
    let correlation = CorrelationResult {
        process: Some({
            let mut proc = process(84, "depmod", "/usr/sbin/depmod", "/usr/sbin/depmod -a");
            proc.maintenance_activity = Some(MaintenanceActivity::PackageManagerHelper);
            proc
        }),
        protected_hits: 0,
    };

    let event = scorer.score(&batch, &correlation);

    assert_eq!(event.level, BehaviorLevel::Observed);
    assert!(event
        .reasons
        .iter()
        .any(|reason| reason == "package-manager helper activity"));
}

#[test]
fn package_manager_detection_does_not_match_unrelated_substrings() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let batch = batch_with_ops(
        FileOperationCounts {
            modified: 8,
            ..Default::default()
        },
        vec!["/tmp/capturer-cache"],
        0,
    );
    let correlation = CorrelationResult {
        process: Some(process(
            88,
            "capturer",
            "/usr/bin/capturer",
            "/usr/bin/capturer --rpm-cache /tmp/capturer-cache",
        )),
        protected_hits: 0,
    };

    let event = scorer.score(&batch, &correlation);

    assert!(!event
        .reasons
        .iter()
        .any(|reason| reason == "package-manager helper activity"));
}

#[test]
fn trusted_maintenance_activity_is_downgraded() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let batch = FileActivityBatch {
        timestamp: Utc::now(),
        source: "userspace_polling".to_string(),
        watched_root: "/usr/lib/firmware".to_string(),
        poll_interval_ms: 1000,
        file_ops: FileOperationCounts {
            modified: 4,
            ..Default::default()
        },
        touched_paths: vec!["/usr/lib/firmware/vendor.bin".to_string()],
        protected_paths_touched: vec!["/usr/lib/firmware/vendor.bin".to_string()],
        rename_extension_targets: Vec::new(),
        content_indicators: crate::ebpf::events::FileContentIndicators {
            unreadable_rewrites: 1,
            high_entropy_rewrites: 1,
        },
        bytes_written: 2 * 1_048_576,
        io_rate_bytes_per_sec: 2 * 1_048_576,
    };
    let mut proc = process(
        101,
        "fwupd",
        "/usr/libexec/fwupd/fwupd",
        "/usr/libexec/fwupd/fwupd --daemon",
    );
    proc.parent_process_name = Some("systemd".to_string());
    proc.parent_command_line = Some("systemd".to_string());
    proc.service_unit = Some("fwupd.service".to_string());
    proc.trust_class = ProcessTrustClass::TrustedPackageManaged;
    proc.maintenance_activity = Some(MaintenanceActivity::TrustedMaintenance);
    let correlation = CorrelationResult {
        process: Some(proc),
        protected_hits: 1,
    };

    let event = scorer.score(&batch, &correlation);

    assert_eq!(event.level, BehaviorLevel::Observed);
    assert!(event
        .reasons
        .iter()
        .any(|reason| reason == "trusted maintenance activity"));
}

#[test]
fn trusted_containerized_service_temp_activity_is_downgraded() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let batch = batch_with_ops(
        FileOperationCounts {
            modified: 5,
            deleted: 5,
            ..Default::default()
        },
        vec!["/tmp/#sql-temptable"],
        2 * 1_048_576,
    );
    let mut proc = process(
        55,
        "mariadbd",
        "/usr/sbin/mariadbd",
        "mariadbd --user=node --datadir=/app/data/mariadb --socket=/app/data/run/mariadb.sock",
    );
    proc.parent_process_name = Some("node".to_string());
    proc.parent_command_line = Some("node server/server.js".to_string());
    proc.container_runtime = Some("docker".to_string());
    proc.container_id = Some("0123456789abcdef0123456789abcdef".to_string());
    let correlation = CorrelationResult {
        process: Some(proc),
        protected_hits: 0,
    };

    let event = scorer.score(&batch, &correlation);

    assert_eq!(event.level, BehaviorLevel::Observed);
    assert!(event
        .reasons
        .iter()
        .any(|reason| reason == "containerized service temp activity"));
}

#[test]
fn agent_internal_activity_is_downgraded() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let batch = FileActivityBatch {
        timestamp: Utc::now(),
        source: "userspace_polling".to_string(),
        watched_root: "/var/lib/bannkenn".to_string(),
        poll_interval_ms: 1000,
        file_ops: FileOperationCounts {
            renamed: 5,
            deleted: 3,
            ..Default::default()
        },
        touched_paths: vec!["/var/lib/bannkenn/policy/state.json".to_string()],
        protected_paths_touched: vec!["/etc/bannkenn/agent.toml".to_string()],
        rename_extension_targets: Vec::new(),
        content_indicators: Default::default(),
        bytes_written: 0,
        io_rate_bytes_per_sec: 0,
    };
    let correlation = CorrelationResult {
        process: Some(process(
            202,
            "bannkenn-agent",
            "/usr/bin/bannkenn-agent",
            "/usr/bin/bannkenn-agent run",
        )),
        protected_hits: 1,
    };

    let event = scorer.score(&batch, &correlation);

    assert_eq!(event.level, BehaviorLevel::Observed);
    assert!(event
        .reasons
        .iter()
        .any(|reason| reason == "agent internal activity"));
}

#[test]
fn containerd_shim_parent_is_not_treated_as_a_shell_parent() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let batch = batch_with_ops(
        FileOperationCounts {
            modified: 5,
            deleted: 5,
            ..Default::default()
        },
        vec!["/tmp/#sql-temptable"],
        2 * 1_048_576,
    );
    let mut proc = process(
        55,
        "mariadbd",
        "/usr/sbin/mariadbd",
        "mariadbd --user=node --datadir=/app/data/mariadb --socket=/app/data/run/mariadb.sock",
    );
    proc.parent_process_name = Some("containerd-shim".to_string());
    proc.parent_command_line =
        Some("/usr/bin/containerd-shim-runc-v2 -namespace moby -id 0123456789abcdef".to_string());
    proc.container_runtime = Some("docker".to_string());
    proc.container_id = Some("0123456789abcdef0123456789abcdef".to_string());
    let correlation = CorrelationResult {
        process: Some(proc),
        protected_hits: 0,
    };

    let event = scorer.score(&batch, &correlation);

    assert!(event
        .reasons
        .iter()
        .any(|reason| reason == "containerized service temp activity"));
}

#[test]
fn real_shell_parent_still_blocks_containerized_service_suppression() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let batch = batch_with_ops(
        FileOperationCounts {
            modified: 5,
            deleted: 5,
            ..Default::default()
        },
        vec!["/tmp/cron-staging"],
        2 * 1_048_576,
    );
    let mut proc = process(
        56,
        "python3",
        "/usr/bin/python3",
        "/usr/bin/python3 /tmp/dropper.py",
    );
    proc.parent_process_name = Some("sh".to_string());
    proc.parent_command_line = Some("/bin/sh -c /usr/bin/python3 /tmp/dropper.py".to_string());
    proc.container_runtime = Some("docker".to_string());
    proc.container_id = Some("fedcba9876543210fedcba9876543210".to_string());
    let correlation = CorrelationResult {
        process: Some(proc),
        protected_hits: 0,
    };

    let event = scorer.score(&batch, &correlation);

    assert!(!event
        .reasons
        .iter()
        .any(|reason| reason == "containerized service temp activity"));
}

#[test]
fn shell_ancestor_anywhere_in_chain_blocks_containerized_service_suppression() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let batch = batch_with_ops(
        FileOperationCounts {
            modified: 5,
            deleted: 5,
            ..Default::default()
        },
        vec!["/tmp/cron-staging"],
        2 * 1_048_576,
    );
    let mut proc = process(
        57,
        "python3",
        "/usr/bin/python3",
        "/usr/bin/python3 /tmp/dropper.py",
    );
    proc.parent_process_name = Some("containerd-shim".to_string());
    proc.parent_command_line =
        Some("/usr/bin/containerd-shim-runc-v2 -namespace moby -id abc".to_string());
    proc.parent_chain = vec![
        ProcessAncestor {
            pid: 200,
            process_name: Some("containerd-shim".to_string()),
            exe_path: Some("/usr/bin/containerd-shim-runc-v2".to_string()),
            command_line: Some(
                "/usr/bin/containerd-shim-runc-v2 -namespace moby -id abc".to_string(),
            ),
        },
        ProcessAncestor {
            pid: 199,
            process_name: Some("sh".to_string()),
            exe_path: Some("/bin/sh".to_string()),
            command_line: Some("/bin/sh -c /usr/bin/python3 /tmp/dropper.py".to_string()),
        },
    ];
    proc.container_runtime = Some("docker".to_string());
    proc.container_id = Some("fedcba9876543210fedcba9876543210".to_string());
    let correlation = CorrelationResult {
        process: Some(proc),
        protected_hits: 0,
    };

    let event = scorer.score(&batch, &correlation);

    assert!(!event
        .reasons
        .iter()
        .any(|reason| reason == "containerized service temp activity"));
}

#[test]
fn overlapping_benign_contexts_do_not_double_subtract_the_same_components() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let batch = batch_with_ops(
        FileOperationCounts {
            renamed: 2,
            modified: 5,
            deleted: 3,
            ..Default::default()
        },
        vec!["/tmp/depmod-cache"],
        2 * 1_048_576,
    );
    let mut proc = process(84, "depmod", "/usr/sbin/depmod", "/usr/sbin/depmod -a");
    proc.parent_process_name = Some("systemd".to_string());
    proc.parent_command_line = Some("systemd".to_string());
    proc.container_runtime = Some("docker".to_string());
    proc.container_id = Some("0123456789abcdef0123456789abcdef".to_string());
    proc.maintenance_activity = Some(MaintenanceActivity::PackageManagerHelper);

    let adjustment = scorer.context_adjustment(
        Some(&proc),
        ScoreComponents {
            protected_path: 0,
            rename: effective_burst_score(
                batch.file_ops.renamed,
                RENAME_BURST_GRACE,
                scorer.rename_score,
            ),
            write: batch.file_ops.modified.saturating_mul(scorer.write_score),
            delete: effective_burst_score(
                batch.file_ops.deleted,
                DELETE_BURST_GRACE,
                scorer.delete_score,
            ),
            throughput: (batch.bytes_written / scorer.bytes_per_score).min(u64::from(u32::MAX))
                as u32,
            directory_spread: 0,
            high_entropy_rewrite: 0,
            unreadable_rewrite: 0,
        },
        build_context_flags(&batch, Some(&proc)),
    );

    assert_eq!(
        adjustment.penalty,
        effective_burst_score(
            batch.file_ops.renamed,
            RENAME_BURST_GRACE,
            scorer.rename_score
        ) + batch.file_ops.modified.saturating_mul(scorer.write_score)
            + effective_burst_score(
                batch.file_ops.deleted,
                DELETE_BURST_GRACE,
                scorer.delete_score
            )
            + (batch.bytes_written / scorer.bytes_per_score).min(u64::from(u32::MAX)) as u32
    );
    assert!(adjustment
        .reasons
        .iter()
        .any(|reason| reason == "package-manager helper activity"));
    assert!(adjustment
        .reasons
        .iter()
        .any(|reason| reason == "containerized service temp activity"));
}

#[test]
fn temp_path_executable_gets_extra_suspicion() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let batch = batch_with_ops(
        FileOperationCounts {
            modified: 5,
            deleted: 2,
            ..Default::default()
        },
        vec!["/tmp/ransom/payload"],
        0,
    );
    let correlation = CorrelationResult {
        process: Some(process(
            99,
            "ransom",
            "/tmp/ransom/payload",
            "/tmp/ransom/payload --encrypt /srv/data",
        )),
        protected_hits: 0,
    };

    let event = scorer.score(&batch, &correlation);

    assert!(
        event.level == BehaviorLevel::Suspicious,
        "score={} reasons={:?}",
        event.score,
        event.reasons
    );
    assert!(event
        .reasons
        .iter()
        .any(|reason| reason == "temp-path executable"));
    assert!(!event
        .reasons
        .iter()
        .any(|reason| reason == "agent internal activity"));
    assert!(event.score >= 30);
}

#[test]
fn process_name_mismatch_adds_bonus() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let batch = FileActivityBatch {
        timestamp: Utc::now(),
        source: "userspace_polling".to_string(),
        watched_root: "/srv/data".to_string(),
        poll_interval_ms: 1000,
        file_ops: FileOperationCounts {
            modified: 7,
            ..Default::default()
        },
        touched_paths: vec!["/srv/data/file.txt".to_string()],
        protected_paths_touched: Vec::new(),
        rename_extension_targets: Vec::new(),
        content_indicators: Default::default(),
        bytes_written: 0,
        io_rate_bytes_per_sec: 0,
    };
    let correlation = CorrelationResult {
        process: Some(process(
            90,
            "sshd",
            "/usr/bin/python3",
            "/usr/bin/python3 /tmp/dropper.py",
        )),
        protected_hits: 0,
    };

    let event = scorer.score(&batch, &correlation);

    assert_eq!(event.level, BehaviorLevel::Suspicious);
    assert!(event
        .reasons
        .iter()
        .any(|reason| reason == "process name/executable mismatch"));
}

#[test]
fn temp_exec_trigger_starts_at_suspicious_and_includes_mismatch_when_present() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let proc = process(91, "cron", "/tmp/payload", "/tmp/payload --run");

    let event = scorer.score_temp_exec_trigger(
        Utc::now(),
        "aya_ringbuf",
        "/tmp",
        "/tmp/payload",
        Some(&proc),
    );

    assert_eq!(event.level, BehaviorLevel::Suspicious);
    assert!(event
        .reasons
        .iter()
        .any(|reason| reason == "temp write followed by execve"));
    assert!(event
        .reasons
        .iter()
        .any(|reason| reason == "process name/executable mismatch"));
}

#[test]
fn raw_score_only_rename_burst_is_downgraded_without_full_behavior_chain() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let batch = FileActivityBatch {
        timestamp: Utc::now(),
        source: "userspace_polling".to_string(),
        watched_root: "/srv/data".to_string(),
        poll_interval_ms: 1000,
        file_ops: FileOperationCounts {
            renamed: 20,
            ..Default::default()
        },
        touched_paths: vec![
            "/srv/data/customer/a.locked".to_string(),
            "/srv/data/customer/b.locked".to_string(),
        ],
        protected_paths_touched: Vec::new(),
        rename_extension_targets: Vec::new(),
        content_indicators: Default::default(),
        bytes_written: 0,
        io_rate_bytes_per_sec: 0,
    };
    let correlation = CorrelationResult {
        process: Some({
            let mut proc = process(
                601,
                "python3",
                "/usr/bin/python3",
                "/usr/bin/python3 /srv/data/rename.py",
            );
            proc.trust_class = ProcessTrustClass::AllowedLocal;
            proc
        }),
        protected_hits: 0,
    };

    let event = scorer.score(&batch, &correlation);

    assert_eq!(event.level, BehaviorLevel::Suspicious);
    assert!(
        event.score >= 60,
        "expected raw score pressure to remain high"
    );
    assert!(event.reasons.iter().any(|reason| {
        reason == "insufficient correlated ransomware-style signals for high-risk escalation"
    }));
    assert!(event
        .reasons
        .iter()
        .any(|reason| reason == "behavior chain signals: meaningful_rename, user_data_targeting"));
}

#[test]
fn raw_fuse_score_without_extra_corroboration_is_held_at_throttle() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let batch = FileActivityBatch {
        timestamp: Utc::now(),
        source: "userspace_polling".to_string(),
        watched_root: "/srv/data".to_string(),
        poll_interval_ms: 1000,
        file_ops: FileOperationCounts {
            modified: 8,
            renamed: 20,
            ..Default::default()
        },
        touched_paths: vec!["/srv/data/customer/archive.enc".to_string()],
        protected_paths_touched: Vec::new(),
        rename_extension_targets: Vec::new(),
        content_indicators: Default::default(),
        bytes_written: 8 * 1_048_576,
        io_rate_bytes_per_sec: 8 * 1_048_576,
    };
    let correlation = CorrelationResult {
        process: Some(process(
            602,
            "python3",
            "/usr/bin/python3",
            "/usr/bin/python3 /srv/data/encrypt.py",
        )),
        protected_hits: 0,
    };

    let event = scorer.score(&batch, &correlation);

    assert_eq!(event.level, BehaviorLevel::HighRisk);
    assert!(
        event.score >= 90,
        "expected raw score pressure to hit fuse range"
    );
    assert!(event.reasons.iter().any(|reason| {
        reason
            == "insufficient correlated ransomware-style signals for containment-candidate escalation"
    }));
    assert!(event.reasons.iter().any(|reason| {
        reason
            == "behavior chain signals: weak_identity, meaningful_rename, repeated_writes, user_data_targeting"
    }));
}

#[test]
fn content_rewrite_signals_raise_risk_and_chain_confidence() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let mut proc = process(
        606,
        "python3",
        "/usr/bin/python3",
        "/usr/bin/python3 /srv/data/job.py",
    );
    proc.first_seen_at = Utc::now() - chrono::Duration::minutes(30);
    let correlation = CorrelationResult {
        process: Some(proc),
        protected_hits: 0,
    };
    let batch = FileActivityBatch {
        timestamp: Utc::now(),
        source: "userspace_polling".to_string(),
        watched_root: "/srv/data".to_string(),
        poll_interval_ms: 1000,
        file_ops: FileOperationCounts {
            modified: 6,
            ..Default::default()
        },
        touched_paths: vec![
            "/srv/data/finance/a.txt".to_string(),
            "/srv/data/hr/b.txt".to_string(),
            "/srv/data/legal/c.txt".to_string(),
        ],
        protected_paths_touched: Vec::new(),
        rename_extension_targets: Vec::new(),
        content_indicators: crate::ebpf::events::FileContentIndicators {
            unreadable_rewrites: 2,
            high_entropy_rewrites: 1,
        },
        bytes_written: 3 * 1_048_576,
        io_rate_bytes_per_sec: 3 * 1_048_576,
    };

    let event = scorer.score(&batch, &correlation);

    assert_eq!(event.level, BehaviorLevel::HighRisk);
    assert!(event
        .reasons
        .iter()
        .any(|reason| reason == "unreadable rewrite x2"));
    assert!(event
        .reasons
        .iter()
        .any(|reason| reason == "high-entropy rewrite x1"));
    assert!(event.reasons.iter().any(|reason| {
        reason
            == "behavior chain signals: weak_identity, high_entropy_rewrite, unreadable_rewrite, repeated_writes, user_data_targeting, directory_spread"
    }));
}

#[test]
fn simulated_ransomware_workload_scores_above_benign_maintenance() {
    let benign_scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let ransomware_scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());

    let benign_batch = FileActivityBatch {
        timestamp: Utc::now(),
        source: "aya_ringbuf".to_string(),
        watched_root: "/usr/lib/firmware".to_string(),
        poll_interval_ms: 1000,
        file_ops: FileOperationCounts {
            modified: 4,
            ..Default::default()
        },
        touched_paths: vec!["/usr/lib/firmware/vendor.bin".to_string()],
        protected_paths_touched: vec!["/usr/lib/firmware/vendor.bin".to_string()],
        rename_extension_targets: Vec::new(),
        content_indicators: crate::ebpf::events::FileContentIndicators {
            unreadable_rewrites: 1,
            high_entropy_rewrites: 1,
        },
        bytes_written: 2 * 1_048_576,
        io_rate_bytes_per_sec: 2 * 1_048_576,
    };
    let benign_correlation = CorrelationResult {
        process: Some({
            let mut proc = process(
                701,
                "fwupd",
                "/usr/libexec/fwupd/fwupd",
                "/usr/libexec/fwupd/fwupd --daemon",
            );
            proc.parent_process_name = Some("systemd".to_string());
            proc.parent_command_line = Some("systemd".to_string());
            proc.service_unit = Some("fwupd.service".to_string());
            proc.trust_class = ProcessTrustClass::TrustedPackageManaged;
            proc.maintenance_activity = Some(MaintenanceActivity::TrustedMaintenance);
            proc
        }),
        protected_hits: 1,
    };

    let ransomware_batch = FileActivityBatch {
        timestamp: Utc::now(),
        source: "aya_ringbuf".to_string(),
        watched_root: "/srv/data".to_string(),
        poll_interval_ms: 1000,
        file_ops: FileOperationCounts {
            modified: 8,
            renamed: 12,
            deleted: 3,
            ..Default::default()
        },
        touched_paths: vec![
            "/srv/data/finance/a.enc".to_string(),
            "/srv/data/hr/b.enc".to_string(),
            "/srv/data/legal/c.enc".to_string(),
        ],
        protected_paths_touched: Vec::new(),
        rename_extension_targets: vec![
            "enc".to_string(),
            "enc".to_string(),
            "enc".to_string(),
            "enc".to_string(),
        ],
        content_indicators: crate::ebpf::events::FileContentIndicators {
            unreadable_rewrites: 2,
            high_entropy_rewrites: 2,
        },
        bytes_written: 8 * 1_048_576,
        io_rate_bytes_per_sec: 8 * 1_048_576,
    };
    let ransomware_correlation = CorrelationResult {
        process: Some({
            let mut proc = process(
                702,
                "ransom",
                "/tmp/ransom/payload",
                "/tmp/ransom/payload --encrypt /srv/data",
            );
            proc.parent_process_name = Some("sh".to_string());
            proc.parent_command_line =
                Some("/bin/sh -c /tmp/ransom/payload --encrypt /srv/data".to_string());
            proc
        }),
        protected_hits: 0,
    };

    let benign = benign_scorer.score(&benign_batch, &benign_correlation);
    let ransomware = ransomware_scorer.score(&ransomware_batch, &ransomware_correlation);

    assert_eq!(benign.level, BehaviorLevel::Observed);
    assert!(matches!(
        ransomware.level,
        BehaviorLevel::HighRisk | BehaviorLevel::ContainmentCandidate
    ));
    assert!(ransomware.score > benign.score);
    assert!(ransomware.reasons.iter().any(|reason| {
        reason
            == "behavior chain signals: weak_identity, meaningful_rename, extension_anomaly, high_entropy_rewrite, unreadable_rewrite, repeated_writes, user_data_targeting, suspicious_lineage, directory_spread, rapid_delete"
    }));
}

#[test]
fn rename_extension_anomaly_adds_weight_and_reason() {
    let baseline_scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let anomaly_scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let mut correlation_process = process(
        603,
        "python3",
        "/usr/bin/python3",
        "/usr/bin/python3 /srv/data/encrypt.py",
    );
    correlation_process.first_seen_at = Utc::now() - chrono::Duration::minutes(30);
    let correlation = CorrelationResult {
        process: Some(correlation_process),
        protected_hits: 0,
    };
    let baseline_batch = FileActivityBatch {
        timestamp: Utc::now(),
        source: "userspace_polling".to_string(),
        watched_root: "/srv/data".to_string(),
        poll_interval_ms: 1000,
        file_ops: FileOperationCounts {
            modified: 5,
            renamed: 5,
            ..Default::default()
        },
        touched_paths: vec![
            "/srv/data/customer/a.enc".to_string(),
            "/srv/data/customer/b.enc".to_string(),
        ],
        protected_paths_touched: Vec::new(),
        rename_extension_targets: Vec::new(),
        content_indicators: Default::default(),
        bytes_written: 3 * 1_048_576,
        io_rate_bytes_per_sec: 3 * 1_048_576,
    };
    let anomaly_batch = FileActivityBatch {
        timestamp: Utc::now(),
        source: "userspace_polling".to_string(),
        watched_root: "/srv/data".to_string(),
        poll_interval_ms: 1000,
        file_ops: FileOperationCounts {
            modified: 5,
            renamed: 5,
            ..Default::default()
        },
        touched_paths: vec![
            "/srv/data/customer/a.enc".to_string(),
            "/srv/data/customer/b.enc".to_string(),
        ],
        protected_paths_touched: Vec::new(),
        rename_extension_targets: vec![
            "enc".to_string(),
            "enc".to_string(),
            "enc".to_string(),
            "enc".to_string(),
        ],
        content_indicators: Default::default(),
        bytes_written: 3 * 1_048_576,
        io_rate_bytes_per_sec: 3 * 1_048_576,
    };

    let baseline = baseline_scorer.score(&baseline_batch, &correlation);
    let anomaly = anomaly_scorer.score(&anomaly_batch, &correlation);

    assert!(anomaly.score > baseline.score);
    assert!(anomaly
        .reasons
        .iter()
        .any(|reason| reason == "rename extension anomaly .enc x4"));
}

#[test]
fn recurrent_medium_confidence_batches_escalate_to_high_risk() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let start = Utc::now();
    let mut proc = process(
        604,
        "python3",
        "/usr/bin/python3",
        "/usr/bin/python3 /srv/data/job.py",
    );
    proc.first_seen_at = start - chrono::Duration::minutes(30);
    let correlation = CorrelationResult {
        process: Some(proc),
        protected_hits: 0,
    };
    let first = FileActivityBatch {
        timestamp: start,
        source: "userspace_polling".to_string(),
        watched_root: "/srv/data".to_string(),
        poll_interval_ms: 1000,
        file_ops: FileOperationCounts {
            modified: 8,
            ..Default::default()
        },
        touched_paths: vec![
            "/srv/data/finance/a.txt".to_string(),
            "/srv/data/hr/b.txt".to_string(),
            "/srv/data/legal/c.txt".to_string(),
        ],
        protected_paths_touched: Vec::new(),
        rename_extension_targets: Vec::new(),
        content_indicators: Default::default(),
        bytes_written: 10 * 1_048_576,
        io_rate_bytes_per_sec: 10 * 1_048_576,
    };
    let second = FileActivityBatch {
        timestamp: start + chrono::Duration::seconds(60),
        source: "userspace_polling".to_string(),
        watched_root: "/srv/data".to_string(),
        poll_interval_ms: 1000,
        file_ops: FileOperationCounts {
            modified: 8,
            ..Default::default()
        },
        touched_paths: vec![
            "/srv/data/finance/d.txt".to_string(),
            "/srv/data/hr/e.txt".to_string(),
            "/srv/data/legal/f.txt".to_string(),
        ],
        protected_paths_touched: Vec::new(),
        rename_extension_targets: Vec::new(),
        content_indicators: Default::default(),
        bytes_written: 10 * 1_048_576,
        io_rate_bytes_per_sec: 10 * 1_048_576,
    };

    let first_event = scorer.score(&first, &correlation);
    let second_event = scorer.score(&second, &correlation);

    assert_eq!(first_event.level, BehaviorLevel::Suspicious);
    assert_eq!(second_event.level, BehaviorLevel::HighRisk);
    assert!(second_event
        .reasons
        .iter()
        .any(|reason| reason == "recent recurrent activity x2"));
    assert!(second_event.reasons.iter().any(|reason| {
        reason
            == "behavior chain signals: weak_identity, repeated_writes, user_data_targeting, directory_spread, recurrence_history"
    }));
}

#[test]
fn weighted_multi_signal_user_data_case_escalates_beyond_simple_burst_scoring() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let batch = FileActivityBatch {
        timestamp: Utc::now(),
        source: "userspace_polling".to_string(),
        watched_root: "/srv/data".to_string(),
        poll_interval_ms: 1000,
        file_ops: FileOperationCounts {
            modified: 6,
            renamed: 8,
            ..Default::default()
        },
        touched_paths: vec![
            "/srv/data/finance/q1.enc".to_string(),
            "/srv/data/hr/payroll.enc".to_string(),
            "/srv/data/legal/contracts.enc".to_string(),
        ],
        protected_paths_touched: Vec::new(),
        rename_extension_targets: Vec::new(),
        content_indicators: Default::default(),
        bytes_written: 3 * 1_048_576,
        io_rate_bytes_per_sec: 3 * 1_048_576,
    };
    let correlation = CorrelationResult {
        process: Some({
            let mut proc = process(
                404,
                "python3",
                "/usr/bin/python3",
                "/usr/bin/python3 /tmp/encrypt.py /srv/data",
            );
            proc.parent_process_name = Some("sh".to_string());
            proc.parent_command_line =
                Some("/bin/sh -c /usr/bin/python3 /tmp/encrypt.py /srv/data".to_string());
            proc
        }),
        protected_hits: 0,
    };

    let event = scorer.score(&batch, &correlation);

    assert_eq!(event.level, BehaviorLevel::HighRisk);
    assert!(event
        .reasons
        .iter()
        .any(|reason| reason == "user/application data targeted"));
    assert!(event
        .reasons
        .iter()
        .any(|reason| reason == "directory spread x3"));
    assert!(event
        .reasons
        .iter()
        .any(|reason| reason == "shell-like parent lineage"));
    assert!(event
        .reasons
        .iter()
        .any(|reason| reason == "unknown process identity"));
    assert!(event
        .reasons
        .iter()
        .any(|reason| reason == "newly observed process"));
}

#[test]
fn environment_profiles_shift_thresholds_without_changing_actions() {
    let batch = FileActivityBatch {
        timestamp: Utc::now(),
        source: "userspace_polling".to_string(),
        watched_root: "/srv/data".to_string(),
        poll_interval_ms: 1000,
        file_ops: FileOperationCounts {
            modified: 4,
            ..Default::default()
        },
        touched_paths: vec!["/srv/data/customer/a.txt".to_string()],
        protected_paths_touched: Vec::new(),
        rename_extension_targets: Vec::new(),
        content_indicators: Default::default(),
        bytes_written: 2 * 1_048_576,
        io_rate_bytes_per_sec: 2 * 1_048_576,
    };
    let mut proc = process(
        605,
        "python3",
        "/usr/bin/python3",
        "/usr/bin/python3 /srv/data/job.py",
    );
    proc.first_seen_at = Utc::now() - chrono::Duration::minutes(30);
    let correlation = CorrelationResult {
        process: Some(proc),
        protected_hits: 0,
    };
    let conservative = CompositeBehaviorScorer::from_config(&ContainmentConfig {
        environment_profile: crate::config::ContainmentEnvironmentProfile::Conservative,
        ..ContainmentConfig::default()
    });
    let balanced = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let aggressive = CompositeBehaviorScorer::from_config(&ContainmentConfig {
        environment_profile: crate::config::ContainmentEnvironmentProfile::Aggressive,
        ..ContainmentConfig::default()
    });

    let conservative_event = conservative.score(&batch, &correlation);
    let balanced_event = balanced.score(&batch, &correlation);
    let aggressive_event = aggressive.score(&batch, &correlation);

    assert_eq!(conservative_event.level, BehaviorLevel::Observed);
    assert_eq!(balanced_event.level, BehaviorLevel::Suspicious);
    assert_eq!(aggressive_event.level, BehaviorLevel::Suspicious);
}

#[test]
fn trusted_process_lineage_reduces_weighted_score() {
    let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
    let batch = FileActivityBatch {
        timestamp: Utc::now(),
        source: "userspace_polling".to_string(),
        watched_root: "/srv/data".to_string(),
        poll_interval_ms: 1000,
        file_ops: FileOperationCounts {
            modified: 5,
            renamed: 7,
            ..Default::default()
        },
        touched_paths: vec![
            "/srv/data/team-a/a.locked".to_string(),
            "/srv/data/team-b/b.locked".to_string(),
            "/srv/data/team-c/c.locked".to_string(),
        ],
        protected_paths_touched: Vec::new(),
        rename_extension_targets: Vec::new(),
        content_indicators: Default::default(),
        bytes_written: 2 * 1_048_576,
        io_rate_bytes_per_sec: 2 * 1_048_576,
    };

    let unknown = scorer.score(
        &batch,
        &CorrelationResult {
            process: Some(process(
                505,
                "python3",
                "/usr/bin/python3",
                "/usr/bin/python3 /srv/data/job.py",
            )),
            protected_hits: 0,
        },
    );
    let trusted = scorer.score(
        &batch,
        &CorrelationResult {
            process: Some({
                let mut proc = process(
                    506,
                    "python3",
                    "/usr/bin/python3",
                    "/usr/bin/python3 /srv/data/job.py",
                );
                proc.trust_class = ProcessTrustClass::TrustedPackageManaged;
                proc.package_name = Some("python3".to_string());
                proc
            }),
            protected_hits: 0,
        },
    );

    assert!(trusted.score < unknown.score);
    assert!(trusted
        .reasons
        .iter()
        .any(|reason| reason == "trusted process lineage"));
}
