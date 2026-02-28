mod auth;
mod config;
mod db;
mod feeds;
mod routes;

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use config::ServerConfig;
use db::Db;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

pub struct AppState {
    pub db: Arc<Db>,
    pub config: Arc<ServerConfig>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing_subscriber::filter::LevelFilter::INFO.into()),
        )
        .init();

    info!("Starting BannKenn server...");

    // Load configuration
    let config = ServerConfig::load()?;
    info!("Configuration loaded: bind={}", config.bind);

    // Create database
    let db = Db::new(&config.db_path).await?;
    info!("Database initialized at {}", config.db_path);

    let db = Arc::new(db);
    let config = Arc::new(config);

    // Start feed task
    feeds::start_feed_task(db.clone()).await;
    info!("Feed task started");

    // Build the router
    let app_state = AppState {
        db: db.clone(),
        config: config.clone(),
    };

    let auth_config = auth::AuthConfig {
        jwt_secret: config.jwt_secret.clone(),
    };

    // Health endpoint (no auth required)
    let health_route = get(routes::health::health);

    // Agent registration (no auth required)
    let agents_register_route = post(routes::agents::register).with_state(Arc::new(
        routes::agents::AppState {
            db: db.clone(),
            jwt_secret: config.jwt_secret.clone(),
        },
    ));

    // Auth middleware (protects POST /decisions only)
    let auth_middleware_layer = middleware::from_fn_with_state(
        Arc::new(auth_config),
        auth::auth_middleware,
    );

    let decisions_state = Arc::new(routes::decisions::AppState { db: db.clone() });

    // Public: GET /api/v1/decisions
    let decisions_read = Router::new()
        .route("/", get(routes::decisions::list))
        .with_state(decisions_state.clone());

    // Protected: POST /api/v1/decisions
    let decisions_write = Router::new()
        .route("/", post(routes::decisions::create))
        .with_state(decisions_state)
        .layer(auth_middleware_layer);

    // Combine all routes
    let router = Router::new()
        .route("/api/v1/health", health_route)
        .route("/api/v1/agents/register", agents_register_route)
        .nest("/api/v1/decisions", decisions_read.merge(decisions_write))
        .layer(TraceLayer::new_for_http());

    // Parse bind address
    let addr: std::net::SocketAddr = config.bind.parse()?;
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Server listening on {}", addr);

    // Setup graceful shutdown
    let server = axum::serve(listener, router);

    tokio::select! {
        result = server => {
            if let Err(e) = result {
                error!("Server error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Shutdown signal received, gracefully shutting down...");
        }
    }

    info!("Server shut down successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_state_creation() {
        let config = ServerConfig::default();
        let config = Arc::new(config);
        assert_eq!(config.bind, "0.0.0.0:3022");
    }
}
