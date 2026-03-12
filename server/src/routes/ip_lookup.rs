use crate::db::Db;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::{net::IpAddr, sync::Arc};

pub struct AppState {
    pub db: Arc<Db>,
}

#[derive(Debug, Deserialize)]
pub struct LookupParams {
    pub ip: String,
    pub history_limit: Option<i64>,
}

pub async fn lookup(
    State(state): State<Arc<AppState>>,
    Query(params): Query<LookupParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let parsed_ip = params
        .ip
        .trim()
        .parse::<IpAddr>()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let history_limit = params.history_limit.unwrap_or(200).clamp(1, 1000);

    let result = state
        .db
        .lookup_ip_activity(&parsed_ip.to_string(), history_limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(result))
}
