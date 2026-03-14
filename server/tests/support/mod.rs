#![allow(dead_code)]

use bannkenn_server::db::{
    BehaviorFileOpsRow, ContainmentOutcomeRow, Db, NewBehaviorEvent, NewContainmentEvent,
};

pub async fn test_db() -> Db {
    Db::new(":memory:").await.expect("Failed to create test DB")
}

pub fn sample_behavior_event(
    agent_name: &str,
    watched_root: &str,
    timestamp: &str,
) -> NewBehaviorEvent {
    NewBehaviorEvent {
        agent_name: agent_name.to_string(),
        source: "ebpf_ringbuf".to_string(),
        watched_root: watched_root.to_string(),
        pid: Some(42),
        process_name: Some("python3".to_string()),
        exe_path: Some("/usr/bin/python3".to_string()),
        command_line: Some("python3 encrypt.py".to_string()),
        correlation_hits: 3,
        file_ops: BehaviorFileOpsRow {
            created: 1,
            modified: 2,
            renamed: 4,
            deleted: 0,
        },
        touched_paths: vec![format!("{}/a.txt", watched_root)],
        protected_paths_touched: Vec::new(),
        bytes_written: 8192,
        io_rate_bytes_per_sec: 4096,
        score: 58,
        reasons: vec!["rename burst".to_string()],
        level: "throttle_candidate".to_string(),
        timestamp: Some(timestamp.to_string()),
    }
}

pub fn sample_containment_event(
    agent_name: &str,
    watched_root: &str,
    state: &str,
    timestamp: &str,
) -> NewContainmentEvent {
    NewContainmentEvent {
        agent_name: agent_name.to_string(),
        state: state.to_string(),
        previous_state: Some("suspicious".to_string()),
        reason: format!("{} threshold crossed", state),
        watched_root: watched_root.to_string(),
        pid: Some(42),
        score: 67,
        actions: vec!["ApplyIoThrottle".to_string()],
        outcomes: vec![ContainmentOutcomeRow {
            enforcer: "cgroup".to_string(),
            applied: false,
            dry_run: true,
            detail: "dry-run".to_string(),
        }],
        timestamp: Some(timestamp.to_string()),
    }
}
