mod support;

use axum::{extract::Path, extract::State, http::StatusCode, Json};
use bannkenn_server::{
    auth::AuthenticatedAgent,
    db::NewContainmentAction,
    routes::containment_actions::{
        self, AckContainmentActionRequest, AppState, CreateContainmentActionRequest,
    },
};
use std::sync::Arc;
use support::test_db;

#[tokio::test]
async fn containment_actions_round_trip_pending_and_acknowledgement() {
    let db = test_db().await;
    db.insert_agent("agent-a", "token-a", None).await.unwrap();

    let created = db
        .create_containment_action(&NewContainmentAction {
            agent_name: "agent-a".to_string(),
            command_kind: "trigger_fuse".to_string(),
            reason: "Operator requested a fuse".to_string(),
            watched_root: Some("/srv/data".to_string()),
            pid: Some(42),
            requested_by: "dashboard".to_string(),
        })
        .await
        .unwrap();

    assert_eq!(created.status, "pending");
    assert_eq!(created.command_kind, "trigger_fuse");

    let pending = db
        .list_pending_containment_actions_by_agent("agent-a", 10)
        .await
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, created.id);

    let completed = db
        .complete_containment_action(
            created.id,
            "agent-a",
            "applied",
            Some("fuse"),
            Some("fuse activated"),
            Some("2026-03-14T12:00:00+00:00"),
        )
        .await
        .unwrap()
        .expect("completed action should exist");

    assert_eq!(completed.status, "applied");
    assert_eq!(completed.resulting_state.as_deref(), Some("fuse"));
    assert_eq!(completed.result_message.as_deref(), Some("fuse activated"));
    assert_eq!(
        completed.executed_at.as_deref(),
        Some("2026-03-14T12:00:00+00:00")
    );

    let pending_after = db
        .list_pending_containment_actions_by_agent("agent-a", 10)
        .await
        .unwrap();
    assert!(pending_after.is_empty());
}

#[tokio::test]
async fn containment_action_handlers_reject_invalid_values() {
    let db = Arc::new(test_db().await);
    let agent_id = db.insert_agent("agent-a", "token-a", None).await.unwrap();
    let state = Arc::new(AppState { db: db.clone() });

    let create_err = containment_actions::create(
        State(state.clone()),
        Path(agent_id),
        Json(CreateContainmentActionRequest {
            command_kind: "pause_world".to_string(),
            reason: "invalid".to_string(),
            watched_root: None,
            pid: None,
        }),
    )
    .await
    .err()
    .expect("invalid command kinds should be rejected");
    assert_eq!(create_err, StatusCode::BAD_REQUEST);

    let action = db
        .create_containment_action(&NewContainmentAction {
            agent_name: "agent-a".to_string(),
            command_kind: "trigger_fuse".to_string(),
            reason: "Operator requested a fuse".to_string(),
            watched_root: Some("/srv/data".to_string()),
            pid: Some(42),
            requested_by: "dashboard".to_string(),
        })
        .await
        .unwrap();

    let ack_err = containment_actions::acknowledge(
        State(state),
        AuthenticatedAgent("agent-a".to_string()),
        Path(action.id),
        Json(AckContainmentActionRequest {
            status: "queued".to_string(),
            resulting_state: None,
            result_message: None,
            executed_at: None,
        }),
    )
    .await
    .err()
    .expect("invalid acknowledgement statuses should be rejected");
    assert_eq!(ack_err, StatusCode::BAD_REQUEST);
}
