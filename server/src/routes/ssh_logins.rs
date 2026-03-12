use crate::auth::AuthenticatedAgent;
use crate::db::{Db, SshLoginRow};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub struct AppState {
    pub db: Arc<Db>,
}

#[derive(Debug, Deserialize)]
pub struct CreateSshLoginRequest {
    pub ip: String,
    pub username: String,
    pub timestamp: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateSshLoginResponse {
    pub id: i64,
}

/// POST /api/v1/ssh-logins — agent-authenticated, records a successful SSH login
pub async fn create(
    State(state): State<Arc<AppState>>,
    agent: AuthenticatedAgent,
    Json(payload): Json<CreateSshLoginRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let id = state
        .db
        .insert_ssh_login_with_timestamp(
            &payload.ip,
            &payload.username,
            &agent.0,
            payload.timestamp.as_deref(),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::CREATED, Json(CreateSshLoginResponse { id })))
}

/// GET /api/v1/ssh-logins — public, returns the 50 most recent SSH login events
pub async fn list(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, StatusCode> {
    let rows: Vec<SshLoginRow> = state
        .db
        .list_ssh_logins(50)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(rows))
}
