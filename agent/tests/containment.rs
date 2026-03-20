use bannkenn_agent::{
    client::ContainmentActionRow,
    config::ContainmentConfig,
    containment::{ContainmentCoordinator, ContainmentState},
    ebpf::events::{BehaviorEvent, BehaviorLevel, FileOperationCounts, ProcessTrustClass},
    enforcement::EnforcementAction,
};
use chrono::{Duration, Utc};

fn event(level: BehaviorLevel, score: u32, pid: Option<u32>) -> BehaviorEvent {
    BehaviorEvent {
        timestamp: Utc::now(),
        source: "test".to_string(),
        watched_root: "/srv/data".to_string(),
        pid,
        parent_pid: Some(1),
        uid: Some(1000),
        gid: Some(1000),
        service_unit: Some("backup.service".to_string()),
        first_seen_at: Some(Utc::now()),
        trust_class: Some(ProcessTrustClass::AllowedLocal),
        trust_policy_name: None,
        maintenance_activity: None,
        trust_policy_visibility: Default::default(),
        package_name: None,
        package_manager: None,
        process_name: Some("python3".to_string()),
        exe_path: Some("/usr/bin/python3".to_string()),
        command_line: Some("python3 encrypt.py".to_string()),
        parent_process_name: Some("systemd".to_string()),
        parent_command_line: Some("systemd".to_string()),
        parent_chain: Vec::new(),
        container_runtime: None,
        container_id: None,
        container_image: None,
        orchestrator: Default::default(),
        container_mounts: Vec::new(),
        correlation_hits: 10,
        file_ops: FileOperationCounts {
            modified: 1,
            ..Default::default()
        },
        touched_paths: vec!["/srv/data/file.txt".to_string()],
        protected_paths_touched: Vec::new(),
        bytes_written: 4096,
        io_rate_bytes_per_sec: 4096,
        score,
        reasons: vec!["test".to_string()],
        level,
    }
}

fn action(
    id: i64,
    command_kind: &str,
    reason: &str,
    watched_root: &str,
    pid: Option<u32>,
    timestamp: &str,
) -> ContainmentActionRow {
    ContainmentActionRow {
        id,
        agent_name: "agent-a".to_string(),
        command_kind: command_kind.to_string(),
        reason: reason.to_string(),
        watched_root: Some(watched_root.to_string()),
        pid,
        requested_by: "dashboard".to_string(),
        status: "pending".to_string(),
        resulting_state: None,
        result_message: None,
        created_at: timestamp.to_string(),
        updated_at: timestamp.to_string(),
        executed_at: None,
    }
}

#[test]
fn suspicious_and_throttle_events_escalate_state() {
    let config = ContainmentConfig {
        enabled: true,
        throttle_enabled: true,
        throttle_action_min_events: 1,
        ..ContainmentConfig::default()
    };
    let start = Utc::now();
    let mut coordinator = ContainmentCoordinator::new(&config);

    let suspicious = coordinator
        .handle_event_at(&event(BehaviorLevel::Suspicious, 35, Some(42)), start)
        .expect("suspicious transition");
    assert_eq!(suspicious.state, ContainmentState::Suspicious);
    assert!(suspicious.actions.is_empty());

    let throttle = coordinator
        .handle_event_at(
            &event(BehaviorLevel::HighRisk, 70, Some(42)),
            start + Duration::seconds(5),
        )
        .expect("throttle transition");
    assert_eq!(throttle.state, ContainmentState::Throttle);
    assert_eq!(throttle.actions.len(), 2);
    assert!(matches!(
        throttle.actions[0],
        EnforcementAction::ApplyIoThrottle { .. }
    ));
    assert!(matches!(
        throttle.actions[1],
        EnforcementAction::ApplyNetworkThrottle { .. }
    ));
}

#[test]
fn fuse_decay_waits_for_rate_limit_then_releases_to_throttle() {
    let config = ContainmentConfig {
        enabled: true,
        throttle_enabled: true,
        fuse_enabled: true,
        auto_fuse_release_min: 0,
        throttle_action_min_events: 1,
        fuse_action_min_events: 1,
        ..ContainmentConfig::default()
    };
    let start = Utc::now();
    let mut coordinator = ContainmentCoordinator::new(&config);

    let fuse = coordinator
        .handle_event_at(
            &event(BehaviorLevel::ContainmentCandidate, 100, Some(77)),
            start,
        )
        .expect("fuse transition");
    assert_eq!(fuse.state, ContainmentState::Fuse);
    assert!(matches!(
        fuse.actions.as_slice(),
        [EnforcementAction::SuspendProcess { pid: 77, .. }]
    ));

    assert!(
        coordinator.tick_at(start + Duration::seconds(30)).is_none(),
        "decay should be rate limited for 60 seconds"
    );

    let decay = coordinator
        .tick_at(start + Duration::seconds(61))
        .expect("decay transition");
    assert_eq!(decay.state, ContainmentState::Throttle);
    assert!(matches!(
        decay.actions.as_slice(),
        [
            EnforcementAction::ResumeProcess { pid: 77, .. },
            EnforcementAction::ApplyIoThrottle { .. },
            EnforcementAction::ApplyNetworkThrottle { .. }
        ]
    ));
}

#[test]
fn repeated_same_level_events_do_not_retransition() {
    let config = ContainmentConfig {
        enabled: true,
        ..ContainmentConfig::default()
    };
    let start = Utc::now();
    let mut coordinator = ContainmentCoordinator::new(&config);

    coordinator
        .handle_event_at(&event(BehaviorLevel::Suspicious, 35, Some(42)), start)
        .expect("initial suspicious transition");

    assert!(coordinator
        .handle_event_at(
            &event(BehaviorLevel::Suspicious, 40, Some(42)),
            start + Duration::seconds(1),
        )
        .is_none());
    assert_eq!(coordinator.state(), ContainmentState::Suspicious);
}

#[test]
fn high_risk_events_are_held_until_repeated_for_auto_throttle() {
    let config = ContainmentConfig {
        enabled: true,
        throttle_enabled: true,
        containment_action_window_secs: 120,
        throttle_action_min_events: 2,
        ..ContainmentConfig::default()
    };
    let start = Utc::now();
    let mut coordinator = ContainmentCoordinator::new(&config);

    let first = coordinator
        .handle_event_at(&event(BehaviorLevel::HighRisk, 70, Some(42)), start)
        .expect("initial suspicious transition");
    assert_eq!(first.state, ContainmentState::Suspicious);
    assert!(first.actions.is_empty());
    assert_eq!(
        first.transition.as_ref().map(|transition| transition.reason.as_str()),
        Some("auto containment held until 2 corroborating high-risk-or-higher events are observed in 120s")
    );

    let second = coordinator
        .handle_event_at(
            &event(BehaviorLevel::HighRisk, 72, Some(42)),
            start + Duration::seconds(5),
        )
        .expect("throttle transition");
    assert_eq!(second.state, ContainmentState::Throttle);
    assert_eq!(second.actions.len(), 2);
}

#[test]
fn containment_candidate_events_require_repeated_candidates_for_fuse() {
    let config = ContainmentConfig {
        enabled: true,
        throttle_enabled: true,
        fuse_enabled: true,
        containment_action_window_secs: 120,
        throttle_action_min_events: 2,
        fuse_action_min_events: 2,
        ..ContainmentConfig::default()
    };
    let start = Utc::now();
    let mut coordinator = ContainmentCoordinator::new(&config);

    let first = coordinator
        .handle_event_at(
            &event(BehaviorLevel::ContainmentCandidate, 90, Some(77)),
            start,
        )
        .expect("initial suspicious transition");
    assert_eq!(first.state, ContainmentState::Suspicious);
    assert!(first.actions.is_empty());

    let second = coordinator
        .handle_event_at(
            &event(BehaviorLevel::ContainmentCandidate, 92, Some(77)),
            start + Duration::seconds(5),
        )
        .expect("fuse transition");
    assert_eq!(second.state, ContainmentState::Fuse);
    assert!(matches!(
        second.actions.as_slice(),
        [EnforcementAction::SuspendProcess { pid: 77, .. }]
    ));
}

#[test]
fn missing_pid_blocks_automatic_containment_actions() {
    let config = ContainmentConfig {
        enabled: true,
        throttle_enabled: true,
        fuse_enabled: true,
        throttle_action_min_events: 1,
        fuse_action_min_events: 1,
        ..ContainmentConfig::default()
    };
    let start = Utc::now();
    let mut coordinator = ContainmentCoordinator::new(&config);

    let decision = coordinator
        .handle_event_at(&event(BehaviorLevel::ContainmentCandidate, 95, None), start)
        .expect("suspicious transition");
    assert_eq!(decision.state, ContainmentState::Suspicious);
    assert!(decision.actions.is_empty());
    assert_eq!(
        decision
            .transition
            .as_ref()
            .map(|transition| transition.reason.as_str()),
        Some("auto containment held because the triggering process PID is unavailable")
    );
}

#[test]
fn manual_fuse_trigger_bypasses_rate_limit_and_moves_to_fuse() {
    let config = ContainmentConfig {
        enabled: true,
        throttle_enabled: true,
        fuse_enabled: true,
        throttle_action_min_events: 1,
        fuse_action_min_events: 1,
        ..ContainmentConfig::default()
    };
    let start = Utc::now();
    let mut coordinator = ContainmentCoordinator::new(&config);

    coordinator
        .handle_event_at(&event(BehaviorLevel::Suspicious, 35, Some(42)), start)
        .expect("initial suspicious transition");

    let result = coordinator.apply_operator_action_at(
        &action(
            1,
            "trigger_fuse",
            "operator request",
            "/srv/data",
            Some(42),
            &start.to_rfc3339(),
        ),
        start + Duration::seconds(1),
    );

    assert!(result.applied);
    assert_eq!(
        result.decision.as_ref().expect("operator decision").state,
        ContainmentState::Fuse
    );
}

#[test]
fn manual_fuse_release_returns_to_throttle_when_enabled() {
    let config = ContainmentConfig {
        enabled: true,
        throttle_enabled: true,
        fuse_enabled: true,
        throttle_action_min_events: 1,
        fuse_action_min_events: 1,
        ..ContainmentConfig::default()
    };
    let start = Utc::now();
    let mut coordinator = ContainmentCoordinator::new(&config);

    coordinator
        .handle_event_at(
            &event(BehaviorLevel::ContainmentCandidate, 100, Some(77)),
            start,
        )
        .expect("fuse transition");

    let result = coordinator.apply_operator_action_at(
        &action(
            2,
            "release_fuse",
            "operator release",
            "/srv/data",
            Some(77),
            &start.to_rfc3339(),
        ),
        start + Duration::seconds(2),
    );

    assert!(result.applied);
    assert_eq!(
        result
            .decision
            .as_ref()
            .expect("operator release decision")
            .state,
        ContainmentState::Throttle
    );
}
