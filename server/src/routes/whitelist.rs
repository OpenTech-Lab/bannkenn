use crate::db::Db;
use crate::ip_pattern::canonicalize_ip_pattern;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

pub struct AppState {
    pub db: Arc<Db>,
}

#[derive(Debug, Deserialize)]
pub struct ListWhitelistParams {
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CreateWhitelistRequest {
    pub ip: String,
    pub note: Option<String>,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListWhitelistParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let limit = params.limit.unwrap_or(500).clamp(1, 5000);
    let rows = state
        .db
        .list_whitelist_entries(limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(rows))
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateWhitelistRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let ip = payload.ip.trim();
    let ip = canonicalize_ip_pattern(ip).ok_or(StatusCode::BAD_REQUEST)?;
    let note = payload
        .note
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let entry = state
        .db
        .upsert_whitelist_entry(&ip, note)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::CREATED, Json(entry)))
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, StatusCode> {
    let deleted = state
        .db
        .delete_whitelist_entry(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}
