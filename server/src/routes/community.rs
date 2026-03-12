use crate::db::Db;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;

pub struct AppState {
    pub db: Arc<Db>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ListCommunityIpsParams {
    pub limit: Option<i64>,
}

pub async fn list_ips(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListCommunityIpsParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let limit = params.limit.unwrap_or(1000).clamp(1, 5000);
    let rows = state
        .db
        .list_community_ips(limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(rows))
}

pub async fn list_feeds(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, StatusCode> {
    let rows = state
        .db
        .list_community_feeds()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(rows))
}

pub async fn list_feed_ips(
    State(state): State<Arc<AppState>>,
    Path(source): Path<String>,
    Query(params): Query<ListCommunityIpsParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let limit = params.limit.unwrap_or(1000).clamp(1, 5000);
    let rows = state
        .db
        .list_community_feed_ips(&source, limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(rows))
}
