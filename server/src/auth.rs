use anyhow::anyhow;
use axum::{
    async_trait,
    extract::{FromRequestParts, Request, State},
    http::{request::Parts, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
}

pub fn create_token(agent_name: &str, secret: &str) -> anyhow::Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow!("Failed to get current time: {}", e))?
        .as_secs() as usize;

    // 1 year = 365 days * 24 hours * 3600 seconds
    let exp = now + (365 * 24 * 3600);

    let claims = Claims {
        sub: agent_name.to_string(),
        exp,
        iat: now,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|e| anyhow!("Failed to encode token: {}", e))?;

    Ok(token)
}

pub fn verify_token(token: &str, secret: &str) -> anyhow::Result<Claims> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|e| anyhow!("Failed to decode token: {}", e))?;

    Ok(token_data.claims)
}

#[derive(Clone)]
pub struct AuthenticatedAgent(pub String);

/// Allow handlers to extract `AuthenticatedAgent` inserted by `auth_middleware`.
#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedAgent
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthenticatedAgent>()
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)
    }
}

pub struct AuthConfig {
    pub jwt_secret: String,
}

pub async fn auth_middleware(
    State(config): State<Arc<AuthConfig>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !auth_header.starts_with("Bearer ") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = &auth_header[7..]; // Remove "Bearer " prefix

    let claims = verify_token(token, &config.jwt_secret).map_err(|_| StatusCode::UNAUTHORIZED)?;

    request
        .extensions_mut()
        .insert(AuthenticatedAgent(claims.sub));

    Ok(next.run(request).await)
}
