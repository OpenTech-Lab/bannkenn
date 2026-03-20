mod support;

use bannkenn_server::db::ContainmentOutcomeRow;
use support::{sample_behavior_event, sample_containment_event, test_db};

#[tokio::test]
async fn behavior_events_round_trip_structured_payloads() {
    let db = test_db().await;

    let mut event = sample_behavior_event("agent-a", "/srv/data", "2026-03-14T09:00:00+00:00");
    event.correlation_hits = 4;
    event.file_ops.created = 1;
    event.file_ops.modified = 2;
    event.file_ops.renamed = 3;
    event.file_ops.deleted = 4;
    event.protected_paths_touched = vec!["/srv/data/secret.txt".to_string()];
    event.score = 67;
    event.reasons = vec!["rename burst".to_string(), "protected path".to_string()];
    event.level = "high_risk".to_string();

    let id = db.insert_behavior_event(&event).await.unwrap();
    assert!(id > 0);

    let rows = db.list_behavior_events(10).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].agent_name, "agent-a");
    assert_eq!(rows[0].file_ops.renamed, 3);
    assert_eq!(rows[0].protected_paths_touched.len(), 1);
    assert_eq!(rows[0].parent_pid, Some(1));
    assert_eq!(rows[0].uid, Some(1000));
    assert_eq!(rows[0].gid, Some(1000));
    assert_eq!(rows[0].service_unit.as_deref(), Some("backup.service"));
    assert_eq!(
        rows[0].first_seen_at.as_deref(),
        Some("2026-03-14T08:30:00+00:00")
    );
    assert_eq!(
        rows[0].trust_class.as_deref(),
        Some("allowed_local_process")
    );
    assert_eq!(rows[0].trust_policy_name.as_deref(), Some("backup-window"));
    assert_eq!(
        rows[0].maintenance_activity.as_deref(),
        Some("trusted_maintenance")
    );
    assert_eq!(rows[0].package_name.as_deref(), Some("python3"));
    assert_eq!(rows[0].package_manager.as_deref(), Some("dpkg"));
    assert_eq!(rows[0].parent_chain.len(), 2);
    assert_eq!(rows[0].parent_chain[0].pid, 1);
    assert_eq!(
        rows[0].parent_chain[0].process_name.as_deref(),
        Some("systemd")
    );
    assert_eq!(
        rows[0].parent_chain[1].exe_path.as_deref(),
        Some("/usr/local/bin/backup-wrapper")
    );
    assert_eq!(rows[0].parent_process_name.as_deref(), Some("systemd"));
    assert_eq!(rows[0].parent_command_line.as_deref(), Some("systemd"));
    assert_eq!(rows[0].container_runtime.as_deref(), Some("docker"));
    assert_eq!(
        rows[0].container_id.as_deref(),
        Some("0123456789abcdef0123456789abcdef")
    );
    assert_eq!(
        rows[0].container_image.as_deref(),
        Some("ghcr.io/acme/backup:1.2.3")
    );
    assert_eq!(rows[0].level, "high_risk");

    let agent_rows = db
        .list_behavior_events_by_agent("agent-a", 10)
        .await
        .unwrap();
    assert_eq!(agent_rows, rows);
}

#[tokio::test]
async fn containment_events_update_latest_status_and_keep_history() {
    let db = test_db().await;

    let mut suspicious = sample_containment_event(
        "agent-a",
        "/srv/data",
        "suspicious",
        "2026-03-14T09:00:00+00:00",
    );
    suspicious.previous_state = Some("normal".to_string());
    suspicious.reason = "suspicious score threshold crossed".to_string();
    suspicious.actions = Vec::new();
    suspicious.outcomes = Vec::new();
    suspicious.score = 35;
    db.record_containment_event(&suspicious).await.unwrap();

    let mut throttle = sample_containment_event(
        "agent-a",
        "/srv/data",
        "throttle",
        "2026-03-14T09:01:00+00:00",
    );
    throttle.reason = "throttle score threshold crossed".to_string();
    throttle.actions = vec!["ApplyIoThrottle".to_string()];
    throttle.outcomes = vec![ContainmentOutcomeRow {
        enforcer: "cgroup".to_string(),
        applied: false,
        dry_run: true,
        detail: "dry-run".to_string(),
    }];
    throttle.score = 65;
    db.record_containment_event(&throttle).await.unwrap();

    let statuses = db.list_containment_statuses(10).await.unwrap();
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].agent_name, "agent-a");
    assert_eq!(statuses[0].state, "throttle");
    assert_eq!(statuses[0].actions, vec!["ApplyIoThrottle"]);
    assert_eq!(statuses[0].outcomes[0].enforcer, "cgroup");

    let history = db
        .list_containment_events_by_agent("agent-a", 10)
        .await
        .unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].state, "throttle");
    assert_eq!(history[1].state, "suspicious");
}

#[tokio::test]
async fn agent_scoped_behavior_and_containment_pages_support_offsets() {
    let db = test_db().await;

    let newest = sample_behavior_event("agent-a", "/srv/data", "2026-03-14T09:03:00+00:00");
    let middle = sample_behavior_event("agent-a", "/srv/data", "2026-03-14T09:02:00+00:00");
    let oldest = sample_behavior_event("agent-a", "/srv/data", "2026-03-14T09:01:00+00:00");
    db.insert_behavior_event(&newest).await.unwrap();
    db.insert_behavior_event(&middle).await.unwrap();
    db.insert_behavior_event(&oldest).await.unwrap();

    let behavior_page = db
        .list_behavior_events_by_agent_page("agent-a", 2, 1)
        .await
        .unwrap();
    assert_eq!(behavior_page.len(), 2);
    assert_eq!(behavior_page[0].created_at, "2026-03-14T09:02:00+00:00");
    assert_eq!(behavior_page[1].created_at, "2026-03-14T09:01:00+00:00");

    let suspicious = sample_containment_event(
        "agent-a",
        "/srv/data",
        "suspicious",
        "2026-03-14T09:03:00+00:00",
    );
    let throttle = sample_containment_event(
        "agent-a",
        "/srv/data",
        "throttle",
        "2026-03-14T09:02:00+00:00",
    );
    let fuse =
        sample_containment_event("agent-a", "/srv/data", "fuse", "2026-03-14T09:01:00+00:00");
    db.record_containment_event(&suspicious).await.unwrap();
    db.record_containment_event(&throttle).await.unwrap();
    db.record_containment_event(&fuse).await.unwrap();

    let containment_page = db
        .list_containment_events_by_agent_page("agent-a", 2, 1)
        .await
        .unwrap();
    assert_eq!(containment_page.len(), 2);
    assert_eq!(containment_page[0].state, "throttle");
    assert_eq!(containment_page[1].state, "fuse");
}

#[tokio::test]
async fn behavior_incidents_correlate_across_agents_and_emit_alerts() {
    let db = test_db().await;

    let mut first = sample_behavior_event("agent-a", "/srv/data", "2026-03-14T09:00:00+00:00");
    first.pid = Some(101);
    first.correlation_hits = 3;
    first.file_ops.created = 0;
    first.file_ops.modified = 2;
    first.file_ops.renamed = 4;
    first.score = 58;
    first.reasons = vec!["rename burst x4".to_string()];

    let mut second = sample_behavior_event("agent-b", "/srv/data", "2026-03-14T09:05:00+00:00");
    second.pid = Some(202);
    second.correlation_hits = 2;
    second.file_ops.created = 0;
    second.file_ops.modified = 1;
    second.file_ops.renamed = 6;
    second.bytes_written = 8192;
    second.io_rate_bytes_per_sec = 2048;
    second.score = 61;
    second.touched_paths = vec!["/srv/data/b.txt".to_string()];
    second.reasons = vec!["rename burst x6".to_string()];

    let first = db.ingest_behavior_event(&first).await.unwrap();
    let second = db.ingest_behavior_event(&second).await.unwrap();
    assert_eq!(first.incident_id, second.incident_id);

    let incidents = db.list_incidents(10).await.unwrap();
    assert_eq!(incidents.len(), 1);
    assert!(incidents[0].cross_agent);
    assert_eq!(incidents[0].correlated_agent_count, 2);
    assert_eq!(incidents[0].event_count, 2);
    assert_eq!(
        incidents[0].title,
        "Cross-agent behavior incident: rename burst"
    );

    let alerts = db.list_admin_alerts(10).await.unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].alert_type, "cross_agent_incident");
    assert_eq!(alerts[0].incident_id, Some(first.incident_id));
}

#[tokio::test]
async fn containment_updates_incident_timeline_and_emits_transition_alert() {
    let db = test_db().await;

    let mut behavior = sample_behavior_event("agent-a", "/srv/data", "2026-03-14T09:00:00+00:00");
    behavior.correlation_hits = 4;
    behavior.file_ops.renamed = 3;
    behavior.protected_paths_touched = vec!["/srv/data/secret.txt".to_string()];
    behavior.score = 67;
    behavior.reasons = vec!["protected path touched".to_string()];

    let behavior = db.ingest_behavior_event(&behavior).await.unwrap();

    let mut containment = sample_containment_event(
        "agent-a",
        "/srv/data",
        "throttle",
        "2026-03-14T09:01:00+00:00",
    );
    containment.reason = "throttle score threshold crossed".to_string();
    containment.score = 67;
    db.record_containment_event(&containment).await.unwrap();

    let incident = db
        .get_incident_detail(behavior.incident_id, 10)
        .await
        .unwrap()
        .expect("incident should exist");
    assert_eq!(incident.incident.event_count, 2);
    assert_eq!(incident.incident.latest_state.as_deref(), Some("throttle"));
    assert_eq!(incident.incident.alert_count, 1);
    assert_eq!(incident.timeline.len(), 2);
    assert_eq!(incident.timeline[0].source_type, "behavior_event");
    assert_eq!(incident.timeline[1].source_type, "containment_event");

    let alerts = db.list_admin_alerts(10).await.unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].alert_type, "containment_transition");
    assert_eq!(alerts[0].incident_id, Some(behavior.incident_id));
}
