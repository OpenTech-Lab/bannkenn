use super::*;
use crate::ebpf::events::{ProcessInfo, ProcessTrustClass};
use chrono::Utc;

#[test]
fn global_shared_risk_reduces_threshold() {
    let snapshot = SharedRiskSnapshot {
        global_threshold_multiplier: 0.5,
        ..Default::default()
    };

    let decision = snapshot.apply(8, "Invalid SSH user");
    assert_eq!(decision.effective_threshold, Some(4));
    assert_eq!(decision.tags, vec!["shared:global"]);
}

#[test]
fn category_campaign_is_more_aggressive_than_global() {
    let snapshot = SharedRiskSnapshot {
        global_threshold_multiplier: 0.5,
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
    };

    let decision = snapshot.apply(8, "Invalid SSH user");
    assert_eq!(decision.effective_threshold, Some(1));
    assert_eq!(
        decision.tags,
        vec!["shared:campaign".to_string(), "shared:global".to_string()]
    );
}

#[test]
fn unrelated_category_does_not_apply() {
    let snapshot = SharedRiskSnapshot {
        categories: vec![SharedRiskCategory {
            category: "Web SQL Injection attempt".to_string(),
            distinct_ips: 3,
            distinct_agents: 2,
            event_count: 3,
            threshold_multiplier: 0.25,
            force_threshold: Some(1),
            label: "shared:campaign".to_string(),
        }],
        ..Default::default()
    };

    let decision = snapshot.apply(8, "Invalid SSH user");
    assert_eq!(decision, SharedRiskDecision::default());
}

#[test]
fn shared_process_profile_matches_only_well_attributed_identity() {
    let snapshot = SharedRiskSnapshot {
        process_profiles: vec![SharedProcessProfile {
            identity: "/usr/bin/python3|backup.service|python3|ghcr.io/acme/backup:1.2.3"
                .to_string(),
            exe_path: "/usr/bin/python3".to_string(),
            service_unit: Some("backup.service".to_string()),
            package_name: Some("python3".to_string()),
            container_image: Some("ghcr.io/acme/backup:1.2.3".to_string()),
            trust_class: "allowed_local_process".to_string(),
            distinct_agents: 2,
            event_count: 4,
            highest_level: "observed".to_string(),
            label: "shared:allowed-lineage".to_string(),
        }],
        ..Default::default()
    };

    let matched = snapshot
        .shared_process_trust(&ProcessInfo {
            pid: 42,
            parent_pid: Some(1),
            uid: Some(1000),
            gid: Some(1000),
            service_unit: Some("backup.service".to_string()),
            first_seen_at: Utc::now(),
            trust_class: ProcessTrustClass::Unknown,
            trust_policy_name: None,
            maintenance_activity: None,
            trust_policy_visibility: Default::default(),
            package_name: Some("python3".to_string()),
            package_manager: None,
            process_name: "python3".to_string(),
            exe_path: "/usr/bin/python3".to_string(),
            command_line: "python3 backup.py".to_string(),
            correlation_hits: 4,
            parent_process_name: Some("systemd".to_string()),
            parent_command_line: Some("systemd".to_string()),
            parent_chain: Vec::new(),
            container_runtime: Some("docker".to_string()),
            container_id: Some("abc".to_string()),
            container_image: Some("ghcr.io/acme/backup:1.2.3".to_string()),
            orchestrator: Default::default(),
            container_mounts: Vec::new(),
        })
        .expect("shared profile should match");

    assert_eq!(matched.trust_class, ProcessTrustClass::AllowedLocal);
    assert_eq!(matched.label, "shared:allowed-lineage");
    assert!(snapshot
        .shared_process_trust(&ProcessInfo {
            service_unit: None,
            package_name: None,
            container_image: None,
            ..ProcessInfo {
                pid: 42,
                parent_pid: Some(1),
                uid: Some(1000),
                gid: Some(1000),
                service_unit: Some("backup.service".to_string()),
                first_seen_at: Utc::now(),
                trust_class: ProcessTrustClass::Unknown,
                trust_policy_name: None,
                maintenance_activity: None,
                trust_policy_visibility: Default::default(),
                package_name: Some("python3".to_string()),
                package_manager: None,
                process_name: "python3".to_string(),
                exe_path: "/usr/bin/python3".to_string(),
                command_line: "python3 backup.py".to_string(),
                correlation_hits: 4,
                parent_process_name: Some("systemd".to_string()),
                parent_command_line: Some("systemd".to_string()),
                parent_chain: Vec::new(),
                container_runtime: Some("docker".to_string()),
                container_id: Some("abc".to_string()),
                container_image: Some("ghcr.io/acme/backup:1.2.3".to_string()),
                orchestrator: Default::default(),
                container_mounts: Vec::new(),
            }
        })
        .is_none());
}
