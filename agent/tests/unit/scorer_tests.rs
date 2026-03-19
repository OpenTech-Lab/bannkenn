use super::*;
use crate::config::ContainmentConfig;
use crate::ebpf::events::{FileActivityBatch, FileOperationCounts, ProcessInfo};
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
        bytes_written,
        io_rate_bytes_per_sec: bytes_written,
    }
}

fn process(pid: u32, process_name: &str, exe_path: &str, command_line: &str) -> ProcessInfo {
    ProcessInfo {
        pid,
        process_name: process_name.to_string(),
        exe_path: exe_path.to_string(),
        command_line: command_line.to_string(),
        correlation_hits: 20,
        parent_process_name: None,
        parent_command_line: None,
        container_runtime: None,
        container_id: None,
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
            renamed: 7,
            ..Default::default()
        },
        touched_paths: vec!["/srv/data/a".to_string()],
        protected_paths_touched: Vec::new(),
        bytes_written: 0,
        io_rate_bytes_per_sec: 0,
    };
    let correlation = CorrelationResult {
        process: Some(ProcessInfo {
            pid: 4242,
            process_name: "python3".to_string(),
            exe_path: "/usr/bin/python3".to_string(),
            command_line: "python3 encrypt.py".to_string(),
            correlation_hits: 20,
            parent_process_name: Some("systemd".to_string()),
            parent_command_line: Some("systemd".to_string()),
            container_runtime: None,
            container_id: None,
        }),
        protected_hits: 0,
    };

    let event = scorer.score(&batch, &correlation);
    assert_eq!(event.level, BehaviorLevel::Suspicious);
    assert!(event.score > 30);
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
        process: Some(process(
            84,
            "depmod",
            "/usr/sbin/depmod",
            "/usr/sbin/depmod -a",
        )),
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

    let adjustment = scorer.context_adjustment(
        &batch,
        Some(&proc),
        batch.file_ops.renamed.saturating_mul(scorer.rename_score),
        batch.file_ops.modified.saturating_mul(scorer.write_score),
        batch.file_ops.deleted.saturating_mul(scorer.delete_score),
        (batch.bytes_written / scorer.bytes_per_score).min(u64::from(u32::MAX)) as u32,
    );

    assert_eq!(
        adjustment.penalty,
        batch.file_ops.renamed.saturating_mul(scorer.rename_score)
            + batch.file_ops.modified.saturating_mul(scorer.write_score)
            + batch.file_ops.deleted.saturating_mul(scorer.delete_score)
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
            modified: 3,
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

    assert_eq!(event.level, BehaviorLevel::Suspicious);
    assert!(event
        .reasons
        .iter()
        .any(|reason| reason == "temp-path executable"));
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
