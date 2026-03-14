use crate::db::Db;
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
pub struct ListParams {
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct DetailParams {
    pub timeline_limit: Option<i64>,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let limit = params.limit.unwrap_or(200).clamp(1, 2000);
    let incidents = state
        .db
        .list_incidents(limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(incidents))
}

pub async fn detail(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(params): Query<DetailParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let timeline_limit = params.timeline_limit.unwrap_or(500).clamp(1, 5000);
    let incident = state
        .db
        .get_incident_detail(id, timeline_limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let Some(incident) = incident else {
        return Err(StatusCode::NOT_FOUND);
    };
    Ok(Json(incident))
}
