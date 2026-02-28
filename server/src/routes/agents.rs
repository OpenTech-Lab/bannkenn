use crate::auth::create_token;
use crate::db::Db;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub struct AppState {
    pub db: Arc<Db>,
    pub jwt_secret: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterAgentRequest {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterAgentResponse {
    pub token: String,
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterAgentRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    // Generate a random 32-byte token and hash it for storage.
    // Done in a block so !Send types (ThreadRng) are dropped before .await.
    let token_hash = {
        let mut rng = rand::thread_rng();
        let mut token_bytes = [0u8; 32];
        rng.fill(&mut token_bytes);
        let mut hasher = Sha256::new();
        hasher.update(&token_bytes);
        format!("{:x}", hasher.finalize())
    };

    // Insert the agent into the database
    state
        .db
        .insert_agent(&payload.name, &token_hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Create a JWT for the agent
    let jwt = create_token(&payload.name, &state.jwt_secret)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterAgentResponse { token: jwt }),
    ))
}
