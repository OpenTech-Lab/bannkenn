use super::*;
use crate::ebpf::events::ProcessTrustClass;
use crate::ebpf::lifecycle::{LifecycleEvent, TrackedProcess};

#[test]
fn correlator_prefers_non_protected_process_with_exact_path_hits() {
    let correlator = ProcessCorrelator::new();
    let batch = FileActivityBatch {
        timestamp: chrono::Utc::now(),
        source: "userspace_polling".to_string(),
        watched_root: "/srv/data".to_string(),
        poll_interval_ms: 1000,
        file_ops: crate::ebpf::events::FileOperationCounts {
            renamed: 3,
            ..Default::default()
        },
        touched_paths: vec!["/srv/data/file-a".to_string()],
        protected_paths_touched: Vec::new(),
        rename_extension_targets: Vec::new(),
        bytes_written: 0,
        io_rate_bytes_per_sec: 0,
    };
    let snapshot = LifecycleSnapshot {
        processes: vec![
            TrackedProcess {
                pid: 1,
                parent_pid: None,
                uid: None,
                gid: None,
                service_unit: Some("systemd.service".to_string()),
                first_seen_at: chrono::Utc::now(),
                trust_class: ProcessTrustClass::TrustedSystem,
                trust_policy_name: None,
                maintenance_activity: None,
                trust_policy_visibility: Default::default(),
                package_name: None,
                package_manager: None,
                process_name: "systemd".to_string(),
                exe_path: "/usr/lib/systemd/systemd".to_string(),
                command_line: "systemd".to_string(),
                parent_process_name: None,
                parent_command_line: None,
                parent_chain: Vec::new(),
                container_runtime: None,
                container_id: None,
                container_image: None,
                open_paths: HashSet::from(["/srv/data/file-a".to_string()]),
                protected: true,
            },
            TrackedProcess {
                pid: 42,
                parent_pid: Some(1),
                uid: Some(1000),
                gid: Some(1000),
                service_unit: Some("backup.service".to_string()),
                first_seen_at: chrono::Utc::now(),
                trust_class: ProcessTrustClass::AllowedLocal,
                trust_policy_name: None,
                maintenance_activity: None,
                trust_policy_visibility: Default::default(),
                package_name: None,
                package_manager: None,
                process_name: "python3".to_string(),
                exe_path: "/usr/bin/python3".to_string(),
                command_line: "python3 encrypt.py".to_string(),
                parent_process_name: Some("systemd".to_string()),
                parent_command_line: Some("systemd".to_string()),
                parent_chain: Vec::new(),
                container_runtime: None,
                container_id: None,
                container_image: None,
                open_paths: HashSet::from([
                    "/srv/data/file-a".to_string(),
                    "/srv/data/file-b".to_string(),
                ]),
                protected: false,
            },
        ],
        events: vec![LifecycleEvent::Exec {
            pid: 42,
            process_name: "python3".to_string(),
            exe_path: "/usr/bin/python3".to_string(),
        }],
    };

    let result = correlator.correlate(&batch, &snapshot);
    assert_eq!(result.process.expect("process").pid, 42);
    assert!(result.protected_hits > 0);
}
