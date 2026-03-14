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
    event.level = "fuse_candidate".to_string();
    event.reasons = vec!["rename burst x4".to_string()];
    event.protected_paths_touched = vec!["/srv/data/secret.txt".to_string()];

    let record =
        BehaviorArchiveRecord::from_ingested_event(17, 5, &event, "2026-03-14T09:00:00+00:00")
            .unwrap();

    assert_eq!(record.sqlite_event_id, 17);
    assert_eq!(record.incident_id, 5);
    assert_eq!(record.file_ops_renamed, 4);
    assert_eq!(record.level, "fuse_candidate");
    assert!(record.reasons_json.contains("rename burst x4"));
}
