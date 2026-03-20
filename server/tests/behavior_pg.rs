mod support;

use bannkenn_server::behavior_pg::{
    archive_index_statements, archive_schema_sql, BehaviorArchiveRecord,
};

#[test]
fn archive_schema_defines_expected_indexes() {
    assert!(archive_schema_sql().contains("behavior_events_archive"));
    assert!(archive_index_statements()
        .iter()
        .any(|statement| statement.contains("agent_name, created_at DESC")));
    assert!(archive_index_statements()
        .iter()
        .any(|statement| statement.contains("level, created_at DESC")));
    assert!(archive_index_statements()
        .iter()
        .any(|statement| statement.contains("watched_root, created_at DESC")));
}

#[test]
fn archive_record_preserves_ingested_behavior_fields() {
    let mut event =
        support::sample_behavior_event("agent-a", "/srv/data", "2026-03-14T09:00:00+00:00");
    event.file_ops.deleted = 1;
    event.score = 88;
    event.level = "containment_candidate".to_string();
    event.reasons = vec!["rename burst x4".to_string()];
    event.protected_paths_touched = vec!["/srv/data/secret.txt".to_string()];

    let record =
        BehaviorArchiveRecord::from_ingested_event(17, 5, &event, "2026-03-14T09:00:00+00:00")
            .unwrap();

    assert_eq!(record.sqlite_event_id, 17);
    assert_eq!(record.incident_id, 5);
    assert_eq!(record.file_ops_renamed, 4);
    assert_eq!(record.parent_pid, Some(1));
    assert_eq!(record.uid, Some(1000));
    assert_eq!(record.gid, Some(1000));
    assert_eq!(record.service_unit.as_deref(), Some("backup.service"));
    assert_eq!(
        record.first_seen_at.as_deref(),
        Some("2026-03-14T08:30:00+00:00")
    );
    assert_eq!(record.trust_class.as_deref(), Some("allowed_local_process"));
    assert_eq!(record.trust_policy_name.as_deref(), Some("backup-window"));
    assert_eq!(
        record.maintenance_activity.as_deref(),
        Some("trusted_maintenance")
    );
    assert_eq!(record.package_name.as_deref(), Some("python3"));
    assert_eq!(record.package_manager.as_deref(), Some("dpkg"));
    assert!(record.parent_chain_json.contains("\"pid\":1"));
    assert_eq!(record.parent_process_name.as_deref(), Some("systemd"));
    assert_eq!(record.parent_command_line.as_deref(), Some("systemd"));
    assert_eq!(record.container_runtime.as_deref(), Some("docker"));
    assert_eq!(
        record.container_id.as_deref(),
        Some("0123456789abcdef0123456789abcdef")
    );
    assert_eq!(
        record.container_image.as_deref(),
        Some("ghcr.io/acme/backup:1.2.3")
    );
    assert!(record
        .orchestrator_json
        .contains("\"platform\":\"kubernetes\""));
    assert!(record
        .container_mounts_json
        .contains("\"mount_type\":\"bind\""));
    assert_eq!(record.level, "containment_candidate");
    assert!(record.reasons_json.contains("rename burst x4"));
}
