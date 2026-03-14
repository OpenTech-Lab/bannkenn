use crate::auth::AuthenticatedAgent;
use crate::db::{BehaviorFileOpsRow, Db, NewBehaviorEvent};
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
pub struct CreateBehaviorEventRequest {
    pub timestamp: Option<String>,
    pub source: String,
    pub watched_root: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub exe_path: Option<String>,
    pub command_line: Option<String>,
    pub correlation_hits: u32,
    pub file_ops: BehaviorFileOpsRow,
    #[serde(default)]
    pub touched_paths: Vec<String>,
    #[serde(default)]
    pub protected_paths_touched: Vec<String>,
    pub bytes_written: u64,
    pub io_rate_bytes_per_sec: u64,
    pub score: u32,
    #[serde(default)]
    pub reasons: Vec<String>,
    pub level: String,
}

#[derive(Debug, Serialize)]
pub struct CreateBehaviorEventResponse {
    pub id: i64,
}

#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub limit: Option<i64>,
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    agent: AuthenticatedAgent,
    Json(payload): Json<CreateBehaviorEventRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let level = payload.level.trim().to_lowercase();
    if !matches!(
        level.as_str(),
        "observed" | "suspicious" | "throttle_candidate" | "fuse_candidate"
    ) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let id = state
        .db
        .insert_behavior_event(&NewBehaviorEvent {
            agent_name: agent.0,
            source: payload.source,
            watched_root: payload.watched_root,
            pid: payload.pid,
            process_name: payload.process_name,
            exe_path: payload.exe_path,
            command_line: payload.command_line,
            correlation_hits: payload.correlation_hits,
            file_ops: payload.file_ops,
            touched_paths: payload.touched_paths,
            protected_paths_touched: payload.protected_paths_touched,
            bytes_written: payload.bytes_written,
            io_rate_bytes_per_sec: payload.io_rate_bytes_per_sec,
            score: payload.score,
            reasons: payload.reasons,
            level,
            timestamp: payload.timestamp,
        })
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((
        StatusCode::CREATED,
        Json(CreateBehaviorEventResponse { id }),
    ))
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let limit = params.limit.unwrap_or(500).clamp(1, 5000);
    let rows = state
        .db
        .list_behavior_events(limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rows))
}
