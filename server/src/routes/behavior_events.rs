use crate::auth::AuthenticatedAgent;
use crate::behavior_pg::{BehaviorArchiveRecord, BehaviorPgArchive};
use crate::db::{BehaviorFileOpsRow, Db, NewBehaviorEvent};
use crate::validation::{cap_string, cap_vec, MAX_STRING_BYTES, MAX_VEC_ITEMS};
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
    pub behavior_archive: Option<Arc<BehaviorPgArchive>>,
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

    let event = NewBehaviorEvent {
        agent_name: agent.0.clone(),
        source: cap_string(payload.source, MAX_STRING_BYTES),
        watched_root: cap_string(payload.watched_root, MAX_STRING_BYTES),
        pid: payload.pid,
        process_name: payload.process_name,
        exe_path: payload.exe_path,
        command_line: payload
            .command_line
            .map(|s| cap_string(s, MAX_STRING_BYTES)),
        correlation_hits: payload.correlation_hits,
        file_ops: payload.file_ops,
        touched_paths: cap_vec(payload.touched_paths, MAX_VEC_ITEMS),
        protected_paths_touched: cap_vec(payload.protected_paths_touched, MAX_VEC_ITEMS),
        bytes_written: payload.bytes_written,
        io_rate_bytes_per_sec: payload.io_rate_bytes_per_sec,
        score: payload.score,
        reasons: cap_vec(payload.reasons, MAX_VEC_ITEMS),
        level,
        timestamp: payload.timestamp,
    };

    let id = state
        .db
        .ingest_behavior_event(&event)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some(archive) = state.behavior_archive.as_ref() {
        let record = BehaviorArchiveRecord::from_ingested_event(
            id.id,
            id.incident_id,
            &event,
            &id.created_at,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if let Err(err) = archive.archive_event(&record).await {
            tracing::error!(
                "failed to archive behavior event {} to postgres: {}",
                id.id,
                err
            );
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(CreateBehaviorEventResponse { id: id.id }),
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
