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
    pub butterfly_shield_enabled: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
pub struct HeartbeatRequest {
    pub butterfly_shield_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAgentRequest {
    pub nickname: String,
}

#[derive(Debug, Deserialize)]
pub struct AgentDecisionsParams {
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct AgentTelemetryParams {
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct AgentBehaviorEventsParams {
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct AgentContainmentParams {
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct SharedRiskResponse {
    pub generated_at: String,
    pub window_secs: i64,
    pub global_risk_score: f64,
    pub global_threshold_multiplier: f64,
    pub categories: Vec<crate::db::SharedRiskCategoryRow>,
}

#[derive(Debug, Serialize)]
pub struct BackfillGeoipResponse {
    pub updated_rows: u64,
    pub latest_ip: Option<String>,
    pub latest_country: Option<String>,
    pub latest_asn_org: Option<String>,
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
        hasher.update(token_bytes);
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
        .map(|row| map_agent_status(row, now))
        .collect::<Vec<_>>();

    Ok(Json(agents))
}

pub async fn detail(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, StatusCode> {
    let Some(agent) = state
        .db
        .get_agent_with_last_seen(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    else {
        return Err(StatusCode::NOT_FOUND);
    };

    Ok(Json(map_agent_status(agent, Utc::now())))
}

pub async fn heartbeat(
    State(state): State<Arc<AppState>>,
    agent: AuthenticatedAgent,
    payload: Option<Json<HeartbeatRequest>>,
) -> Result<impl IntoResponse, StatusCode> {
    let butterfly_shield_enabled = payload.and_then(|p| p.butterfly_shield_enabled);
    state
        .db
        .upsert_agent_heartbeat(&agent.0, butterfly_shield_enabled)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn shared_risk_profile(
    State(state): State<Arc<AppState>>,
    _agent: AuthenticatedAgent,
) -> Result<impl IntoResponse, StatusCode> {
    let profile = state
        .db
        .compute_shared_risk_profile(600)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(SharedRiskResponse {
        generated_at: profile.generated_at,
        window_secs: profile.window_secs,
        global_risk_score: profile.global_risk_score,
        global_threshold_multiplier: profile.global_threshold_multiplier,
        categories: profile.categories,
    }))
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

pub async fn list_decisions(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(params): Query<AgentDecisionsParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let limit = params.limit.unwrap_or(500).clamp(1, 2000);
    let Some(agent_name) = state
        .db
        .get_agent_name_by_id(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    else {
        return Err(StatusCode::NOT_FOUND);
    };

    let decisions = state
        .db
        .list_decisions_by_source(&agent_name, limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(decisions))
}

pub async fn list_telemetry(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(params): Query<AgentTelemetryParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let limit = params.limit.unwrap_or(2000).clamp(1, 10000);
    let Some(agent_name) = state
        .db
        .get_agent_name_by_id(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    else {
        return Err(StatusCode::NOT_FOUND);
    };

    let telemetry = state
        .db
        .list_telemetry_by_source(&agent_name, limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(telemetry))
}

pub async fn list_behavior_events(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(params): Query<AgentBehaviorEventsParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let limit = params.limit.unwrap_or(1000).clamp(1, 5000);
    let Some(agent_name) = state
        .db
        .get_agent_name_by_id(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    else {
        return Err(StatusCode::NOT_FOUND);
    };

    let behavior_events = state
        .db
        .list_behavior_events_by_agent(&agent_name, limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(behavior_events))
}

pub async fn list_containment(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(params): Query<AgentContainmentParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let limit = params.limit.unwrap_or(500).clamp(1, 2000);
    let Some(agent_name) = state
        .db
        .get_agent_name_by_id(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    else {
        return Err(StatusCode::NOT_FOUND);
    };

    let containment_events = state
        .db
        .list_containment_events_by_agent(&agent_name, limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(containment_events))
}

pub async fn backfill_geoip(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, StatusCode> {
    let Some(agent_name) = state
        .db
        .get_agent_name_by_id(id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    else {
        return Err(StatusCode::NOT_FOUND);
    };

    let updated_rows = state
        .db
        .backfill_decision_geoip_for_source(&agent_name)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let latest = state
        .db
        .list_decisions_by_source(&agent_name, 1)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .into_iter()
        .next();

    Ok(Json(BackfillGeoipResponse {
        updated_rows,
        latest_ip: latest.as_ref().map(|d| d.ip.clone()),
        latest_country: latest.as_ref().and_then(|d| d.country.clone()),
        latest_asn_org: latest.as_ref().and_then(|d| d.asn_org.clone()),
    }))
}

fn map_agent_status(row: crate::db::AgentStatusRow, now: DateTime<Utc>) -> AgentStatusResponse {
    let status = match row
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
        id: row.id,
        name: row.name,
        uuid: row.uuid,
        nickname: row.nickname,
        created_at: row.created_at,
        last_seen_at: row.last_seen_at,
        status,
        butterfly_shield_enabled: row.butterfly_shield_enabled,
    }
}
