use crate::auth::AuthenticatedAgent;
use crate::db::{ContainmentActionRow, Db, NewContainmentAction};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub struct AppState {
    pub db: Arc<Db>,
}

#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CreateContainmentActionRequest {
    pub command_kind: String,
    pub reason: String,
    pub watched_root: Option<String>,
    pub pid: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct CreateContainmentActionResponse {
    pub action: ContainmentActionRow,
}

#[derive(Debug, Deserialize)]
pub struct AckContainmentActionRequest {
    pub status: String,
    pub resulting_state: Option<String>,
    pub result_message: Option<String>,
    pub executed_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AckContainmentActionResponse {
    pub action: ContainmentActionRow,
}

fn is_valid_command_kind(value: &str) -> bool {
    matches!(value, "trigger_fuse" | "release_fuse")
}

fn is_valid_ack_status(value: &str) -> bool {
    matches!(value, "applied" | "failed")
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<i64>,
    Json(payload): Json<CreateContainmentActionRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let command_kind = payload.command_kind.trim().to_lowercase();
    if !is_valid_command_kind(&command_kind) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let Some(agent_name) = state
        .db
        .get_agent_name_by_id(agent_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    else {
        return Err(StatusCode::NOT_FOUND);
    };

    let action = state
        .db
        .create_containment_action(&NewContainmentAction {
            agent_name,
            command_kind,
            reason: payload.reason,
            watched_root: payload
                .watched_root
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            pid: payload.pid,
            requested_by: "dashboard".to_string(),
        })
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((
        StatusCode::CREATED,
        Json(CreateContainmentActionResponse { action }),
    ))
}

pub async fn list_by_agent(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<i64>,
    Query(params): Query<ListParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let limit = params.limit.unwrap_or(50).clamp(1, 500);
    let Some(agent_name) = state
        .db
        .get_agent_name_by_id(agent_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    else {
        return Err(StatusCode::NOT_FOUND);
    };

    let actions = state
        .db
        .list_containment_actions_by_agent(&agent_name, limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(actions))
}

pub async fn list_pending(
    State(state): State<Arc<AppState>>,
    agent: AuthenticatedAgent,
    Query(params): Query<ListParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let actions = state
        .db
        .list_pending_containment_actions_by_agent(&agent.0, limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(actions))
}

pub async fn acknowledge(
    State(state): State<Arc<AppState>>,
    agent: AuthenticatedAgent,
    Path(action_id): Path<i64>,
    Json(payload): Json<AckContainmentActionRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let status = payload.status.trim().to_lowercase();
    if !is_valid_ack_status(&status) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let action = state
        .db
        .complete_containment_action(
            action_id,
            &agent.0,
            &status,
            payload.resulting_state.as_deref(),
            payload.result_message.as_deref(),
            payload.executed_at.as_deref(),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let Some(action) = action else {
        return Err(StatusCode::NOT_FOUND);
    };

    Ok(Json(AckContainmentActionResponse { action }))
}
