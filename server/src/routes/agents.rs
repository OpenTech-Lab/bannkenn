use crate::auth::{create_token, AuthenticatedAgent};
use crate::db::Db;
use axum::{
    extract::Path, extract::Query, extract::State, http::StatusCode, response::IntoResponse, Json,
};
use chrono::{DateTime, Duration, Utc};
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
    pub uuid: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterAgentResponse {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct ListAgentsParams {
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct AgentStatusResponse {
    pub id: i64,
    pub name: String,
    pub uuid: Option<String>,
    pub nickname: Option<String>,
    pub created_at: String,
    pub last_seen_at: Option<String>,
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAgentRequest {
    pub nickname: String,
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterAgentRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let token_hash = {
        let mut rng = rand::thread_rng();
        let mut token_bytes = [0u8; 32];
        rng.fill(&mut token_bytes);
        let mut hasher = Sha256::new();
        hasher.update(&token_bytes);
        format!("{:x}", hasher.finalize())
    };

    state
        .db
        .insert_agent(&payload.name, &token_hash, payload.uuid.as_deref())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let jwt = create_token(&payload.name, &state.jwt_secret)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterAgentResponse { token: jwt }),
    ))
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListAgentsParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let limit = params.limit.unwrap_or(200).clamp(1, 1000);
    let rows = state
        .db
        .list_agents_with_last_seen(limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let now = Utc::now();
    let agents = rows
        .into_iter()
        .map(|a| {
            let status = match a
                .last_seen_at
                .as_ref()
                .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                .map(|dt| dt.with_timezone(&Utc))
            {
                Some(last_seen) if now.signed_duration_since(last_seen) <= Duration::minutes(2) => {
                    "online".to_string()
                }
                Some(_) => "offline".to_string(),
                None => "unknown".to_string(),
            };

            AgentStatusResponse {
                id: a.id,
                name: a.name,
                uuid: a.uuid,
                nickname: a.nickname,
                created_at: a.created_at,
                last_seen_at: a.last_seen_at,
                status,
            }
        })
        .collect::<Vec<_>>();

    Ok(Json(agents))
}

pub async fn heartbeat(
    State(state): State<Arc<AppState>>,
    agent: AuthenticatedAgent,
) -> Result<impl IntoResponse, StatusCode> {
    state
        .db
        .upsert_agent_heartbeat(&agent.0)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn update_nickname(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(payload): Json<UpdateAgentRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    state
        .db
        .update_agent_nickname(id, &payload.nickname)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn delete_agent(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, StatusCode> {
    state
        .db
        .delete_agent(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}
