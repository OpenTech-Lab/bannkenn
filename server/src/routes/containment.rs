use crate::auth::AuthenticatedAgent;
use crate::db::{ContainmentOutcomeRow, Db, NewContainmentEvent};
use axum::{
    extract::{Query, State},
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
pub struct CreateContainmentRequest {
    pub timestamp: Option<String>,
    pub state: String,
    pub previous_state: Option<String>,
    pub reason: String,
    pub watched_root: String,
    pub pid: Option<u32>,
    pub score: u32,
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub outcomes: Vec<ContainmentOutcomeRow>,
}

#[derive(Debug, Serialize)]
pub struct CreateContainmentResponse {
    pub id: i64,
}

#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub limit: Option<i64>,
}

fn is_valid_state(value: &str) -> bool {
    matches!(value, "normal" | "suspicious" | "throttle" | "fuse")
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    agent: AuthenticatedAgent,
    Json(payload): Json<CreateContainmentRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let state_name = payload.state.trim().to_lowercase();
    if !is_valid_state(&state_name) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let previous_state = payload
        .previous_state
        .map(|value| value.trim().to_lowercase());
    if previous_state
        .as_deref()
        .is_some_and(|value| !is_valid_state(value))
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let id = state
        .db
        .record_containment_event(&NewContainmentEvent {
            agent_name: agent.0,
            state: state_name,
            previous_state,
            reason: payload.reason,
            watched_root: payload.watched_root,
            pid: payload.pid,
            score: payload.score,
            actions: payload.actions,
            outcomes: payload.outcomes,
            timestamp: payload.timestamp,
        })
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::CREATED, Json(CreateContainmentResponse { id })))
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let limit = params.limit.unwrap_or(200).clamp(1, 2000);
    let rows = state
        .db
        .list_containment_statuses(limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rows))
}
