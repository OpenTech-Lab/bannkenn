use crate::{auth, behavior_pg::BehaviorPgArchive, config::ServerConfig, db::Db, routes};
use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

pub fn build_router(
    db: Arc<Db>,
    config: ServerConfig,
    behavior_archive: Option<Arc<BehaviorPgArchive>>,
) -> Router {
    let config = Arc::new(config);
    let auth_config = auth::AuthConfig {
        jwt_secret: config.jwt_secret.clone(),
    };

    let auth_middleware_layer =
        middleware::from_fn_with_state(Arc::new(auth_config), auth::auth_middleware);

    let agents_state = Arc::new(routes::agents::AppState {
        db: db.clone(),
        jwt_secret: config.jwt_secret.clone(),
    });
    let agents_public_router = Router::new()
        .route("/", get(routes::agents::list))
        .route("/register", post(routes::agents::register))
        .with_state(agents_state.clone());
    let containment_actions_state =
        Arc::new(routes::containment_actions::AppState { db: db.clone() });

    let agents_protected_router = Router::new()
        .route("/heartbeat", post(routes::agents::heartbeat))
        .route("/shared-risk", get(routes::agents::shared_risk_profile))
        .with_state(agents_state.clone())
        .merge(
            Router::new()
                .route(
                    "/containment-actions/pending",
                    get(routes::containment_actions::list_pending),
                )
                .route(
                    "/containment-actions/:id/ack",
                    post(routes::containment_actions::acknowledge),
                )
                .with_state(containment_actions_state.clone()),
        )
        .layer(auth_middleware_layer.clone());

    let agents_admin_router = Router::new()
        .route("/:id/backfill-geoip", post(routes::agents::backfill_geoip))
        .route("/:id/telemetry", get(routes::agents::list_telemetry))
        .route("/:id/decisions", get(routes::agents::list_decisions))
        .route(
            "/:id/behavior-events",
            get(routes::agents::list_behavior_events),
        )
        .route("/:id/containment", get(routes::agents::list_containment))
        .route(
            "/:id",
            get(routes::agents::detail)
                .patch(routes::agents::update_nickname)
                .delete(routes::agents::delete_agent),
        )
        .with_state(agents_state)
        .merge(
            Router::new()
                .route(
                    "/:id/containment-actions",
                    get(routes::containment_actions::list_by_agent),
                )
                .route(
                    "/:id/containment-actions",
                    post(routes::containment_actions::create),
                )
                .with_state(containment_actions_state),
        );

    let decisions_state = Arc::new(routes::decisions::AppState { db: db.clone() });
    let ip_lookup_state = Arc::new(routes::ip_lookup::AppState { db: db.clone() });
    let telemetry_state = Arc::new(routes::telemetry::AppState { db: db.clone() });
    let behavior_events_state = Arc::new(routes::behavior_events::AppState {
        db: db.clone(),
        behavior_archive,
    });
    let containment_state = Arc::new(routes::containment::AppState { db: db.clone() });
    let incidents_state = Arc::new(routes::incidents::AppState { db: db.clone() });
    let alerts_state = Arc::new(routes::alerts::AppState { db: db.clone() });
    let community_state = Arc::new(routes::community::AppState { db: db.clone() });
    let ssh_logins_state = Arc::new(routes::ssh_logins::AppState { db: db.clone() });
    let whitelist_state = Arc::new(routes::whitelist::AppState { db: db.clone() });

    let decisions_read = Router::new()
        .route("/", get(routes::decisions::list))
        .with_state(decisions_state.clone());
    let decisions_write = Router::new()
        .route("/", post(routes::decisions::create))
        .with_state(decisions_state)
        .layer(auth_middleware_layer.clone());

    let telemetry_read = Router::new()
        .route("/", get(routes::telemetry::list))
        .with_state(telemetry_state.clone());
    let telemetry_write = Router::new()
        .route("/", post(routes::telemetry::create))
        .with_state(telemetry_state)
        .layer(auth_middleware_layer.clone());

    let behavior_events_read = Router::new()
        .route("/", get(routes::behavior_events::list))
        .with_state(behavior_events_state.clone());
    let behavior_events_write = Router::new()
        .route("/", post(routes::behavior_events::create))
        .with_state(behavior_events_state)
        .layer(auth_middleware_layer.clone());

    let containment_read = Router::new()
        .route("/", get(routes::containment::list))
        .with_state(containment_state.clone());
    let containment_write = Router::new()
        .route("/", post(routes::containment::create))
        .with_state(containment_state.clone())
        .layer(auth_middleware_layer.clone());

    let incidents_read = Router::new()
        .route("/", get(routes::incidents::list))
        .route("/:id", get(routes::incidents::detail))
        .with_state(incidents_state);

    let alerts_read = Router::new()
        .route("/", get(routes::alerts::list))
        .with_state(alerts_state);

    let ssh_logins_read = Router::new()
        .route("/", get(routes::ssh_logins::list))
        .with_state(ssh_logins_state.clone());
    let ssh_logins_write = Router::new()
        .route("/", post(routes::ssh_logins::create))
        .with_state(ssh_logins_state)
        .layer(auth_middleware_layer.clone());

    Router::new()
        .route("/api/v1/health", get(routes::health::health))
        .nest(
            "/api/v1/agents",
            agents_public_router
                .merge(agents_protected_router)
                .merge(agents_admin_router),
        )
        .nest("/api/v1/decisions", decisions_read.merge(decisions_write))
        .route(
            "/api/v1/ip-lookup",
            get(routes::ip_lookup::lookup).with_state(ip_lookup_state),
        )
        .nest("/api/v1/telemetry", telemetry_read.merge(telemetry_write))
        .nest(
            "/api/v1/behavior_events",
            behavior_events_read.merge(behavior_events_write),
        )
        .nest(
            "/api/v1/containment",
            containment_read.merge(containment_write).merge(
                Router::new()
                    .route("/events", get(routes::containment::list_events))
                    .with_state(containment_state.clone()),
            ),
        )
        .nest("/api/v1/incidents", incidents_read)
        .nest("/api/v1/alerts", alerts_read)
        .nest(
            "/api/v1/ssh-logins",
            ssh_logins_read.merge(ssh_logins_write),
        )
        .nest(
            "/api/v1/whitelist",
            Router::new()
                .route(
                    "/",
                    get(routes::whitelist::list).post(routes::whitelist::create),
                )
                .route("/:id", delete(routes::whitelist::delete))
                .with_state(whitelist_state),
        )
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
        .layer(TraceLayer::new_for_http())
}
