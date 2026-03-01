use crate::auth::AuthenticatedAgent;
use crate::db::Db;
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
pub struct CreateTelemetryRequest {
    pub ip: String,
    pub reason: String,
    pub level: String,
    pub log_path: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateTelemetryResponse {
    pub id: i64,
}

#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub limit: Option<i64>,
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    agent: AuthenticatedAgent,
    Json(payload): Json<CreateTelemetryRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let level = payload.level.trim().to_lowercase();
    if level != "alert" && level != "block" && level != "listed" {
        return Err(StatusCode::BAD_REQUEST);
    }

    let id = state
        .db
        .insert_telemetry_event(
            &payload.ip,
            &payload.reason,
            &level,
            &agent.0,
            payload.log_path.as_deref(),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::CREATED, Json(CreateTelemetryResponse { id })))
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let limit = params.limit.unwrap_or(500).clamp(1, 5000);

    let rows = state
        .db
        .list_telemetry(limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(rows))
}
