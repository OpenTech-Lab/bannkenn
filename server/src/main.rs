mod auth;
mod config;
mod db;
mod feeds;
mod geoip;
mod routes;

use axum::{
    middleware,
    routing::{get, patch, post},
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

    // Run geo backfill in background so startup/healthcheck are not blocked on large datasets.
    let db_for_backfill = db.clone();
    tokio::spawn(async move {
        match db_for_backfill.backfill_decision_geoip_unknowns().await {
            Ok(count) => info!("GeoIP backfill complete: {} decision rows updated", count),
            Err(err) => error!("GeoIP backfill failed: {}", err),
        }
    });

    // Start feed task
    feeds::start_feed_task(db.clone()).await;
    info!("Feed task started");

    let auth_config = auth::AuthConfig {
        jwt_secret: config.jwt_secret.clone(),
    };

    // Health endpoint (no auth required)
    let health_route = get(routes::health::health);

    // Auth middleware (protects POST /decisions only)
    let auth_middleware_layer =
        middleware::from_fn_with_state(Arc::new(auth_config), auth::auth_middleware);

    // Agent registration/listing is public; heartbeat is protected
    let agents_state = Arc::new(routes::agents::AppState {
        db: db.clone(),
        jwt_secret: config.jwt_secret.clone(),
    });
    let agents_public_router = Router::new()
        .route("/", get(routes::agents::list))
        .route("/register", post(routes::agents::register))
        .with_state(agents_state.clone());

    let agents_protected_router = Router::new()
        .route("/heartbeat", post(routes::agents::heartbeat))
        .with_state(agents_state.clone())
        .layer(auth_middleware_layer.clone());

    let agents_admin_router = Router::new()
        .route("/:id/backfill-geoip", post(routes::agents::backfill_geoip))
        .route("/:id/decisions", get(routes::agents::list_decisions))
        .route(
            "/:id",
            patch(routes::agents::update_nickname).delete(routes::agents::delete_agent),
        )
        .with_state(agents_state);

    let decisions_state = Arc::new(routes::decisions::AppState { db: db.clone() });
    let community_state = Arc::new(routes::community::AppState { db: db.clone() });

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
        .nest(
            "/api/v1/agents",
            agents_public_router
                .merge(agents_protected_router)
                .merge(agents_admin_router),
        )
        .nest("/api/v1/decisions", decisions_read.merge(decisions_write))
        .route(
            "/api/v1/community/ips",
            get(routes::community::list_ips).with_state(community_state.clone()),
        )
        .route(
            "/api/v1/community/feeds",
            get(routes::community::list_feeds).with_state(community_state.clone()),
        )
        .route(
            "/api/v1/community/feeds/:source/ips",
            get(routes::community::list_feed_ips).with_state(community_state),
        )
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
