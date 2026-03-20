use super::*;
use crate::config::ContainmentConfig;
use crate::ebpf::events::ProcessTrustClass;
use crate::ebpf::events::{
    BehaviorLevel, RAW_BEHAVIOR_EVENT_KIND_FILE_ACTIVITY, RAW_BEHAVIOR_EVENT_KIND_PROCESS_EXEC,
};
use crate::ebpf::lifecycle::{LifecycleSnapshot, TrackedProcess};
use crate::shared_risk::SharedRiskSnapshot;
use chrono::Utc;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::test]
async fn simulated_mass_rename_triggers_score_above_suspicious_threshold() {
    let root = std::env::temp_dir().join(format!("bannkenn-phase1-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();

    let mut open_files = Vec::new();
    for idx in 0..11 {
        let path = root.join(format!("file-{}.txt", idx));
        fs::write(&path, format!("payload-{}", idx)).unwrap();
    }

    let mut config = ContainmentConfig {
        enabled: true,
        watch_paths: vec![root.display().to_string()],
        ..ContainmentConfig::default()
    };
    config
        .protected_pid_allowlist
        .retain(|entry| entry != "bannkenn-agent");
    let mut sensor = SensorManager::from_config(
        &config,
        Arc::new(RwLock::new(SharedRiskSnapshot::default())),
    )
    .expect("sensor should be enabled");
    assert!(
        sensor.poll_once().await.unwrap().is_empty(),
        "baseline poll"
    );

    for idx in 0..11 {
        let from = root.join(format!("file-{}.txt", idx));
        open_files.push(fs::File::open(&from).unwrap());
        let to = root.join(format!("file-{}.locked", idx));
        fs::rename(&from, &to).unwrap();
    }

    let events = sensor.poll_once().await.unwrap();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert!(event.file_ops.renamed >= 11);
    assert!(
        event.score > 30,
        "score={} reasons={:?} process={:?} exe={:?}",
        event.score,
        event.reasons,
        event.process_name,
        event.exe_path
    );
    assert_eq!(event.level, BehaviorLevel::Suspicious);
    assert_eq!(event.pid, Some(std::process::id()));

    drop(open_files);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn lifecycle_ring_events_are_translated_without_duplicate_pid_entries() {
    let mut events = vec![LifecycleEvent::Exec {
        pid: 44,
        process_name: "python3".to_string(),
        exe_path: "/usr/bin/python3".to_string(),
    }];
    let raw = RawBehaviorRingEvent {
        pid: 44,
        event_kind: RAW_BEHAVIOR_EVENT_KIND_PROCESS_EXEC,
        bytes_written: 0,
        created: 0,
        modified: 0,
        renamed: 0,
        deleted: 0,
        protected_path_touched: 0,
        path_len: 0,
        process_name_len: 7,
        path: [0; RAW_BEHAVIOR_PATH_CAPACITY],
        process_name: [0; crate::ebpf::events::RAW_BEHAVIOR_PROCESS_CAPACITY],
    };
    let mut raw = raw;
    raw.process_name[..7].copy_from_slice(b"python3");

    merge_lifecycle_events(&mut events, raw_ring_event_to_lifecycle_event(raw));
    assert_eq!(events.len(), 1);
}

#[test]
fn file_activity_ring_events_ignore_lifecycle_translation() {
    let raw = RawBehaviorRingEvent {
        pid: 7,
        event_kind: RAW_BEHAVIOR_EVENT_KIND_FILE_ACTIVITY,
        bytes_written: 2048,
        created: 0,
        modified: 1,
        renamed: 0,
        deleted: 0,
        protected_path_touched: 1,
        path_len: 13,
        process_name_len: 7,
        path: [0; RAW_BEHAVIOR_PATH_CAPACITY],
        process_name: [0; crate::ebpf::events::RAW_BEHAVIOR_PROCESS_CAPACITY],
    };
    let mut raw = raw;
    raw.path[..13].copy_from_slice(b"/srv/data.txt");
    raw.process_name[..7].copy_from_slice(b"python3");

    assert!(raw_ring_event_to_lifecycle_event(raw).is_none());
    let batch = raw_ring_event_to_batch(raw, &[PathBuf::from("/srv")], 1000).expect("batch");
    assert_eq!(batch.bytes_written, 2048);
    assert_eq!(
        batch.protected_paths_touched,
        vec!["/srv/data.txt".to_string()]
    );
}

#[test]
fn activity_batches_are_coalesced_per_source_and_root() {
    let root = "/srv".to_string();
    let batches = vec![
        FileActivityBatch {
            timestamp: Utc::now(),
            source: "aya_ringbuf".to_string(),
            watched_root: root.clone(),
            poll_interval_ms: 1000,
            file_ops: FileOperationCounts {
                created: 0,
                modified: 2,
                renamed: 0,
                deleted: 0,
            },
            touched_paths: vec!["/srv/a.txt".to_string()],
            protected_paths_touched: vec!["/srv/a.txt".to_string()],
            rename_extension_targets: Vec::new(),
            content_indicators: Default::default(),
            bytes_written: 1024,
            io_rate_bytes_per_sec: 1024,
        },
        FileActivityBatch {
            timestamp: Utc::now(),
            source: "aya_ringbuf".to_string(),
            watched_root: root.clone(),
            poll_interval_ms: 1000,
            file_ops: FileOperationCounts {
                created: 1,
                modified: 1,
                renamed: 1,
                deleted: 0,
            },
            touched_paths: vec!["/srv/b.txt".to_string(), "/srv/a.txt".to_string()],
            protected_paths_touched: vec!["/srv/b.txt".to_string()],
            rename_extension_targets: Vec::new(),
            content_indicators: Default::default(),
            bytes_written: 2048,
            io_rate_bytes_per_sec: 2048,
        },
    ];

    let merged = coalesce_activity_batches(batches);
    assert_eq!(merged.len(), 1);
    let batch = &merged[0];
    assert_eq!(batch.file_ops.created, 1);
    assert_eq!(batch.file_ops.modified, 3);
    assert_eq!(batch.file_ops.renamed, 1);
    assert_eq!(batch.bytes_written, 3072);
    assert_eq!(
        batch.touched_paths,
        vec!["/srv/a.txt".to_string(), "/srv/b.txt".to_string()]
    );
    assert_eq!(
        batch.protected_paths_touched,
        vec!["/srv/a.txt".to_string(), "/srv/b.txt".to_string()]
    );
}

#[test]
fn content_profile_tracker_flags_unreadable_and_high_entropy_rewrites() {
    let root = std::env::temp_dir().join(format!("bannkenn-profile-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("notes.txt");
    fs::write(&path, "hello world ".repeat(64)).unwrap();

    let mut tracker = ContentProfileTracker::new(vec![root.clone()], 2048);
    tracker.ensure_initialized();

    let payload = (0..2048)
        .map(|index| (index % 256) as u8)
        .collect::<Vec<_>>();
    fs::write(&path, payload).unwrap();

    let mut batch = FileActivityBatch {
        timestamp: Utc::now(),
        source: "userspace_polling".to_string(),
        watched_root: root.display().to_string(),
        poll_interval_ms: 1000,
        file_ops: FileOperationCounts {
            modified: 1,
            ..Default::default()
        },
        touched_paths: vec![path.display().to_string()],
        protected_paths_touched: Vec::new(),
        rename_extension_targets: Vec::new(),
        content_indicators: Default::default(),
        bytes_written: 2048,
        io_rate_bytes_per_sec: 2048,
    };

    tracker.annotate_batches(std::slice::from_mut(&mut batch));

    assert_eq!(batch.content_indicators.unreadable_rewrites, 1);
    assert_eq!(batch.content_indicators.high_entropy_rewrites, 1);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn content_profile_tracker_ignores_benign_text_rewrites() {
    let root = std::env::temp_dir().join(format!("bannkenn-profile-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("notes.txt");
    fs::write(&path, "hello world ".repeat(64)).unwrap();

    let mut tracker = ContentProfileTracker::new(vec![root.clone()], 2048);
    tracker.ensure_initialized();

    fs::write(&path, "updated notes ".repeat(64)).unwrap();

    let mut batch = FileActivityBatch {
        timestamp: Utc::now(),
        source: "userspace_polling".to_string(),
        watched_root: root.display().to_string(),
        poll_interval_ms: 1000,
        file_ops: FileOperationCounts {
            modified: 1,
            ..Default::default()
        },
        touched_paths: vec![path.display().to_string()],
        protected_paths_touched: Vec::new(),
        rename_extension_targets: Vec::new(),
        content_indicators: Default::default(),
        bytes_written: 2048,
        io_rate_bytes_per_sec: 2048,
    };

    tracker.annotate_batches(std::slice::from_mut(&mut batch));

    assert_eq!(batch.content_indicators.unreadable_rewrites, 0);
    assert_eq!(batch.content_indicators.high_entropy_rewrites, 0);

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn userspace_backend_backs_off_when_tree_is_idle() {
    let root = std::env::temp_dir().join(format!("bannkenn-idle-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let file = root.join("file.txt");
    fs::write(&file, "hello").unwrap();

    let mut backend = UserspacePollingBackend {
        poll_interval_ms: 1000,
        roots: vec![PollingRootState {
            root: root.clone(),
            previous: None,
            idle_scan_streak: 0,
            skip_polls_remaining: 0,
        }],
    };

    assert!(backend.poll_batches(&[]).await.unwrap().batches.is_empty());
    assert_eq!(backend.roots[0].idle_scan_streak, 0);
    assert_eq!(backend.roots[0].skip_polls_remaining, 0);

    assert!(backend.poll_batches(&[]).await.unwrap().batches.is_empty());
    assert_eq!(backend.roots[0].idle_scan_streak, 1);
    assert_eq!(backend.roots[0].skip_polls_remaining, 1);

    assert!(backend.poll_batches(&[]).await.unwrap().batches.is_empty());
    assert_eq!(
        backend.roots[0].skip_polls_remaining, 0,
        "third poll should be skipped instead of rescanning the tree"
    );

    fs::write(&file, "hello-again").unwrap();
    let result = backend.poll_batches(&[]).await.unwrap();
    assert_eq!(result.batches.len(), 1);
    assert_eq!(backend.roots[0].idle_scan_streak, 0);
    assert_eq!(backend.roots[0].skip_polls_remaining, 0);

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn recent_temp_write_followed_by_exec_emits_trigger_event() {
    let root = std::env::temp_dir().join(format!("bannkenn-exec-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();

    let config = ContainmentConfig {
        enabled: true,
        watch_paths: vec![root.display().to_string()],
        ..ContainmentConfig::default()
    };
    let mut sensor = SensorManager::from_config(
        &config,
        Arc::new(RwLock::new(SharedRiskSnapshot::default())),
    )
    .expect("sensor should be enabled");
    sensor.recent_temp_writes.insert(
        "/tmp/payload".to_string(),
        RecentTempWrite {
            recorded_at: Instant::now(),
            watched_root: "/tmp".to_string(),
        },
    );
    let lifecycle = LifecycleSnapshot {
        processes: vec![TrackedProcess {
            pid: 77,
            parent_pid: Some(1),
            uid: Some(0),
            gid: Some(0),
            service_unit: Some("cron.service".to_string()),
            first_seen_at: chrono::Utc::now(),
            trust_class: ProcessTrustClass::TrustedSystem,
            trust_policy_name: None,
            maintenance_activity: None,
            trust_policy_visibility: Default::default(),
            package_name: None,
            package_manager: None,
            process_name: "cron".to_string(),
            exe_path: "/tmp/payload".to_string(),
            command_line: "/tmp/payload --run".to_string(),
            parent_process_name: Some("systemd".to_string()),
            parent_command_line: Some("systemd".to_string()),
            parent_chain: Vec::new(),
            container_runtime: None,
            container_id: None,
            container_image: None,
            orchestrator: Default::default(),
            container_mounts: Vec::new(),
            open_paths: BTreeSet::new().into_iter().collect(),
            protected: false,
        }],
        events: vec![LifecycleEvent::Exec {
            pid: 77,
            process_name: "cron".to_string(),
            exe_path: "/tmp/payload".to_string(),
        }],
    };

    let events = sensor.build_temp_exec_events(&lifecycle);

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].level, BehaviorLevel::Suspicious);
    assert!(events[0]
        .reasons
        .iter()
        .any(|reason| reason == "temp write followed by execve"));
    assert!(events[0]
        .reasons
        .iter()
        .any(|reason| reason == "process name/executable mismatch"));

    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn ringbuf_exec_events_fall_back_to_tracked_process_exe_path() {
    let root =
        std::env::temp_dir().join(format!("bannkenn-exec-fallback-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();

    let config = ContainmentConfig {
        enabled: true,
        watch_paths: vec![root.display().to_string()],
        ..ContainmentConfig::default()
    };
    let mut sensor = SensorManager::from_config(
        &config,
        Arc::new(RwLock::new(SharedRiskSnapshot::default())),
    )
    .expect("sensor should be enabled");
    sensor.recent_temp_writes.insert(
        "/tmp/payload".to_string(),
        RecentTempWrite {
            recorded_at: Instant::now(),
            watched_root: "/tmp".to_string(),
        },
    );
    let lifecycle = LifecycleSnapshot {
        processes: vec![TrackedProcess {
            pid: 88,
            parent_pid: Some(1),
            uid: Some(0),
            gid: Some(0),
            service_unit: Some("payload.service".to_string()),
            first_seen_at: chrono::Utc::now(),
            trust_class: ProcessTrustClass::AllowedLocal,
            trust_policy_name: None,
            maintenance_activity: None,
            trust_policy_visibility: Default::default(),
            package_name: None,
            package_manager: None,
            process_name: "payload".to_string(),
            exe_path: "/tmp/payload".to_string(),
            command_line: "/tmp/payload --run".to_string(),
            parent_process_name: Some("systemd".to_string()),
            parent_command_line: Some("systemd".to_string()),
            parent_chain: Vec::new(),
            container_runtime: None,
            container_id: None,
            container_image: None,
            orchestrator: Default::default(),
            container_mounts: Vec::new(),
            open_paths: std::collections::HashSet::new(),
            protected: false,
        }],
        events: vec![LifecycleEvent::Exec {
            pid: 88,
            process_name: "payload".to_string(),
            exe_path: "payload".to_string(),
        }],
    };

    let events = sensor.build_temp_exec_events(&lifecycle);

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].touched_paths, vec!["/tmp/payload".to_string()]);

    let _ = fs::remove_dir_all(root);
}
