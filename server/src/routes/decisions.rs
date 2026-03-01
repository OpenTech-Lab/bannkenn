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
pub struct CreateDecisionRequest {
    pub ip: String,
    pub reason: String,
    pub action: String,
}

#[derive(Debug, Serialize)]
pub struct CreateDecisionResponse {
    pub id: i64,
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    agent: AuthenticatedAgent,
    Json(payload): Json<CreateDecisionRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let id = state
        .db
        .insert_decision(&payload.ip, &payload.reason, &payload.action, &agent.0)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::CREATED, Json(CreateDecisionResponse { id })))
}

#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub since_id: Option<i64>,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let decisions = match params.since_id {
        Some(id) => state
            .db
            .list_decisions_since(id, 500)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        None => state
            .db
            .list_decisions(100)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    };

    Ok(Json(decisions))
}
