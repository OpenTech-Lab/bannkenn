use super::*;

#[test]
fn test_default_config() {
    let config = AgentConfig::default();
    assert_eq!(config.log_path, "/var/log/auth.log");
    assert_eq!(config.threshold, 5);
    assert_eq!(config.window_secs, 60);
}

#[test]
fn test_config_serialization() {
    let config = AgentConfig {
        server_url: "http://localhost:8080".to_string(),
        jwt_token: "token123".to_string(),
        ca_cert_path: Some("/tmp/server-ca.pem".to_string()),
        agent_name: "test-agent".to_string(),
        uuid: "test-uuid".to_string(),
        log_path: "/var/log/auth.log".to_string(),
        log_paths: vec!["/var/log/auth.log".to_string()],
        threshold: 3,
        window_secs: 120,
        butterfly_shield: None,
        burst: None,
        risk_level: None,
        event_risk: None,
        campaign: None,
        mmdb_dir: None,
        containment: Some(ContainmentConfig::default()),
    };

    let toml_str = toml::to_string(&config).unwrap();
    let deserialized: AgentConfig = toml::from_str(&toml_str).unwrap();

    assert_eq!(config.server_url, deserialized.server_url);
    assert_eq!(config.jwt_token, deserialized.jwt_token);
    assert_eq!(config.ca_cert_path, deserialized.ca_cert_path);
    assert_eq!(config.threshold, deserialized.threshold);
    assert_eq!(config.containment, deserialized.containment);
}

#[test]
fn runtime_defaults_enable_campaign_when_missing() {
    let config = AgentConfig::default().apply_runtime_detection_defaults();
    let campaign = config
        .campaign
        .expect("runtime defaults should populate campaign config");
    assert!(campaign.enabled);
    assert_eq!(campaign.distinct_ips_threshold, 3);
}

#[test]
fn runtime_defaults_populate_containment_config_without_enabling_it() {
    let config = AgentConfig::default().apply_runtime_detection_defaults();
    let containment = config
        .containment
        .expect("runtime defaults should populate containment config");
    assert!(!containment.enabled);
    assert!(containment.dry_run);
    assert!(!containment.fuse_enabled);
    assert_eq!(containment.suspicious_score, 30);
    assert_eq!(containment.throttle_io_read_bps, 4 * 1024 * 1024);
    assert_eq!(containment.throttle_io_write_bps, 1024 * 1024);
    assert_eq!(containment.throttle_network_kbit, 1024);
    assert_eq!(containment.management_allow_ports, vec![22]);
    assert_eq!(
        containment.environment_profile,
        crate::config::ContainmentEnvironmentProfile::Balanced
    );
    assert_eq!(containment.high_entropy_rewrite_score, 8);
    assert_eq!(containment.unreadable_rewrite_score, 10);
    assert_eq!(containment.extension_anomaly_score, 5);
    assert_eq!(containment.extension_anomaly_min_count, 3);
    assert_eq!(containment.user_data_bonus, 8);
    assert_eq!(containment.trusted_process_penalty, 6);
    assert_eq!(containment.allowed_local_penalty, 3);
    assert_eq!(containment.directory_spread_score, 4);
    assert_eq!(containment.shell_parent_bonus, 10);
    assert_eq!(containment.recent_process_bonus, 6);
    assert_eq!(containment.recent_process_window_secs, 600);
    assert_eq!(containment.meaningful_rename_count, 8);
    assert_eq!(containment.meaningful_write_count, 5);
    assert_eq!(containment.high_risk_min_signals, 4);
    assert_eq!(containment.containment_candidate_min_signals, 5);
    assert_eq!(containment.recurrence_score, 6);
    assert_eq!(containment.recurrence_window_secs, 900);
    assert_eq!(containment.recurrence_min_events, 2);
    assert!(containment.auto_containment_requires_pid);
    assert_eq!(containment.containment_action_window_secs, 120);
    assert_eq!(containment.throttle_action_min_events, 2);
    assert_eq!(containment.fuse_action_min_events, 2);
    assert_eq!(containment.content_profile_sample_bytes, 2048);
    assert!(containment
        .protected_pid_allowlist
        .contains(&"bannkenn-agent".to_string()));
    assert!(containment.trust_policies.is_empty());
}

#[test]
fn containment_trust_policy_round_trips() {
    let config = AgentConfig {
        server_url: "http://localhost:8080".to_string(),
        jwt_token: "token123".to_string(),
        ca_cert_path: None,
        agent_name: "test-agent".to_string(),
        uuid: "test-uuid".to_string(),
        log_path: "/var/log/auth.log".to_string(),
        log_paths: vec!["/var/log/auth.log".to_string()],
        threshold: 3,
        window_secs: 120,
        butterfly_shield: None,
        burst: None,
        risk_level: None,
        event_risk: None,
        campaign: None,
        mmdb_dir: None,
        containment: Some(ContainmentConfig {
            trust_policies: vec![TrustPolicyRule {
                name: "backup-window".to_string(),
                exe_paths: vec!["/usr/bin/rsync".to_string()],
                package_names: vec!["rsync".to_string()],
                service_units: vec!["backup.service".to_string()],
                container_images: vec!["ghcr.io/acme/backup:1.2.3".to_string()],
                trust_class: crate::ebpf::events::ProcessTrustClass::TrustedPackageManaged,
                visibility: TrustPolicyVisibility::Hidden,
                maintenance_windows: vec![MaintenanceWindow {
                    weekdays: vec!["sat".to_string(), "sun".to_string()],
                    start: "01:00".to_string(),
                    end: "05:00".to_string(),
                }],
            }],
            ..ContainmentConfig::default()
        }),
    };

    let toml_str = toml::to_string(&config).unwrap();
    let deserialized: AgentConfig = toml::from_str(&toml_str).unwrap();
    let containment = deserialized.containment.expect("containment config");
    let policy = containment
        .trust_policies
        .first()
        .expect("trust policy should round-trip");

    assert_eq!(policy.name, "backup-window");
    assert_eq!(policy.exe_paths, vec!["/usr/bin/rsync"]);
    assert_eq!(policy.package_names, vec!["rsync"]);
    assert_eq!(policy.service_units, vec!["backup.service"]);
    assert_eq!(policy.container_images, vec!["ghcr.io/acme/backup:1.2.3"]);
    assert_eq!(
        policy.trust_class,
        crate::ebpf::events::ProcessTrustClass::TrustedPackageManaged
    );
    assert_eq!(policy.visibility, TrustPolicyVisibility::Hidden);
    assert_eq!(policy.maintenance_windows.len(), 1);
}

#[test]
fn maintenance_window_matches_overnight_ranges() {
    let window = MaintenanceWindow {
        weekdays: vec!["sat".to_string()],
        start: "23:00".to_string(),
        end: "02:00".to_string(),
    };

    assert!(window.matches_weekday_and_time(
        chrono::Weekday::Sat,
        chrono::NaiveTime::from_hms_opt(23, 30, 0).unwrap(),
    ));
    assert!(window.matches_weekday_and_time(
        chrono::Weekday::Sun,
        chrono::NaiveTime::from_hms_opt(1, 30, 0).unwrap(),
    ));
    assert!(!window.matches_weekday_and_time(
        chrono::Weekday::Sun,
        chrono::NaiveTime::from_hms_opt(3, 0, 0).unwrap(),
    ));
}

#[test]
fn offline_agent_state_round_trips() {
    let dir = std::env::temp_dir().join(format!("bannkenn-offline-state-{}", uuid::Uuid::new_v4()));
    let path = dir.join("offline.toml");
    let state = OfflineAgentState {
        known_blocked_ips: HashMap::from([("203.0.113.10".to_string(), "agent".to_string())]),
        whitelisted_ips: vec!["198.51.100.7".to_string()],
        shared_risk_snapshot: SharedRiskSnapshot {
            generated_at: "2026-03-10T00:00:00Z".to_string(),
            window_secs: 600,
            global_risk_score: 0.8,
            global_threshold_multiplier: 0.6,
            categories: Vec::new(),
            process_profiles: Vec::new(),
        },
    };

    state.save(&path).unwrap();
    let loaded = OfflineAgentState::load(&path);
    assert_eq!(loaded, state);

    let _ = fs::remove_dir_all(dir);
}
