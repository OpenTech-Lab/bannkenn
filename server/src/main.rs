mod auth;
mod behavior_pg;
mod config;
mod db;
mod feeds;
mod geoip;
mod ip_pattern;
mod routes;

use anyhow::{bail, Context};
use axum::{
    body::Body,
    http::Request,
    middleware,
    routing::{delete, get, patch, post},
    Router,
};
use behavior_pg::BehaviorPgArchive;
use config::{ServerConfig, ServerTlsConfig};
use db::Db;
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use rustls::{Certificate, PrivateKey};
use std::{
    fs::File,
    io::BufReader,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::{net::TcpListener, sync::watch, task::JoinSet};
use tokio_rustls::TlsAcceptor;
use tower::util::ServiceExt as _;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

pub struct AppState {
    pub db: Arc<Db>,
    pub config: Arc<ServerConfig>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if matches!(std::env::args().nth(1).as_deref(), Some("healthcheck")) {
        return run_healthcheck().await;
    }

    init_tracing();
    run_server().await
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing_subscriber::filter::LevelFilter::INFO.into()),
        )
        .init();
}

async fn run_server() -> anyhow::Result<()> {
    info!("Starting BannKenn server...");

    // Load configuration
    let config = ServerConfig::load()?;
    info!(
        "Configuration loaded: bind={} local_bind={:?} tls_enabled={}",
        config.bind,
        config.local_bind,
        config.tls_config()?.is_some()
    );

    // Create database
    let db = Db::new(&config.db_path).await?;
    info!("Database initialized at {}", config.db_path);

    let db = Arc::new(db);
    let behavior_archive = if let Some(database_url) = config.behavior_pg_url.as_deref() {
        let archive = BehaviorPgArchive::connect(database_url).await?;
        info!("Optional PostgreSQL behavior archive initialized");
        Some(Arc::new(archive))
    } else {
        None
    };

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

    // Start cross-agent campaign detection task.
    // Every 60 seconds: scan recent telemetry from all agents, find attack
    // categories that appear from many distinct IPs across multiple agents,
    // and auto-create block decisions for every involved IP.
    let db_for_campaign = db.clone();
    tokio::spawn(async move {
        let interval = tokio::time::Duration::from_secs(60);
        info!("Campaign detection task started (interval=60s)");

        loop {
            tokio::time::sleep(interval).await;

            // Configuration: campaign declared when ≥5 distinct IPs from ≥2 agents
            // use the same attack category within the last 10 minutes.
            match db_for_campaign.detect_campaign_ips(600, 5, 2).await {
                Ok(campaign_ips) if !campaign_ips.is_empty() => {
                    info!(
                        "Campaign detection: {} IP(s) identified across agents",
                        campaign_ips.len()
                    );
                    for (ip, category) in campaign_ips {
                        let reason = format!("Campaign auto-block: {}", category);
                        match db_for_campaign
                            .insert_decision(&ip, &reason, "block", "campaign")
                            .await
                        {
                            Ok(Some(id)) => info!(
                                "Campaign auto-block: IP={} category='{}' decision_id={}",
                                ip, category, id
                            ),
                            Ok(None) => info!(
                                "Campaign auto-block skipped for whitelisted IP={} category='{}'",
                                ip, category
                            ),
                            Err(e) => {
                                error!("Failed to insert campaign decision for {}: {}", ip, e)
                            }
                        }
                    }
                }
                Ok(_) => {
                    // No campaigns detected this cycle.
                }
                Err(e) => error!("Campaign detection failed: {}", e),
            }
        }
    });

    let router = build_router(db.clone(), config.clone(), behavior_archive);
    let config = Arc::new(config);
    serve_router(router, config).await?;

    info!("Server shut down successfully");
    Ok(())
}

fn build_router(
    db: Arc<Db>,
    config: ServerConfig,
    behavior_archive: Option<Arc<BehaviorPgArchive>>,
) -> Router {
    let config = Arc::new(config);
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
        .route("/shared-risk", get(routes::agents::shared_risk_profile))
        .with_state(agents_state.clone())
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
            patch(routes::agents::update_nickname).delete(routes::agents::delete_agent),
        )
        .with_state(agents_state);

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

    // Public: GET /api/v1/decisions
    let decisions_read = Router::new()
        .route("/", get(routes::decisions::list))
        .with_state(decisions_state.clone());

    // Protected: POST /api/v1/decisions
    let decisions_write = Router::new()
        .route("/", post(routes::decisions::create))
        .with_state(decisions_state)
        .layer(auth_middleware_layer.clone());

    // Public: GET /api/v1/telemetry
    let telemetry_read = Router::new()
        .route("/", get(routes::telemetry::list))
        .with_state(telemetry_state.clone());

    // Protected: POST /api/v1/telemetry
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
        .with_state(containment_state)
        .layer(auth_middleware_layer.clone());

    let incidents_read = Router::new()
        .route("/", get(routes::incidents::list))
        .route("/:id", get(routes::incidents::detail))
        .with_state(incidents_state);

    let alerts_read = Router::new()
        .route("/", get(routes::alerts::list))
        .with_state(alerts_state);

    // Public: GET /api/v1/ssh-logins
    let ssh_logins_read = Router::new()
        .route("/", get(routes::ssh_logins::list))
        .with_state(ssh_logins_state.clone());

    // Protected: POST /api/v1/ssh-logins
    let ssh_logins_write = Router::new()
        .route("/", post(routes::ssh_logins::create))
        .with_state(ssh_logins_state)
        .layer(auth_middleware_layer.clone());

    Router::new()
        .route("/api/v1/health", health_route)
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
            containment_read.merge(containment_write),
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

async fn serve_router(router: Router, config: Arc<ServerConfig>) -> anyhow::Result<()> {
    let public_addr: SocketAddr = config.bind.parse()?;
    let local_addr = parse_optional_bind(config.local_bind.as_deref())?;

    if let Some(local_addr) = local_addr {
        if listener_addresses_conflict(public_addr, local_addr) {
            bail!(
                "local_bind {} conflicts with bind {}. Use a different port for the loopback-only listener.",
                local_addr,
                public_addr
            );
        }
    }

    let tls_config = config
        .tls_config()?
        .map(|tls_files| load_tls_server_config(&tls_files))
        .transpose()?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut listeners = JoinSet::new();

    if let Some(local_addr) = local_addr {
        info!("Local plain HTTP listener enabled on {}", local_addr);
        listeners.spawn(run_http_listener(
            local_addr,
            router.clone(),
            shutdown_rx.clone(),
        ));
    }

    if let Some(tls_config) = tls_config {
        info!("Native TLS API listener enabled on https://{}", public_addr);
        listeners.spawn(run_https_listener(
            public_addr,
            router,
            tls_config,
            shutdown_rx.clone(),
        ));
    } else {
        info!("Plain HTTP listener enabled on http://{}", public_addr);
        listeners.spawn(run_http_listener(public_addr, router, shutdown_rx.clone()));
    }

    let mut shutdown_error = tokio::select! {
        signal = shutdown_signal() => {
            info!("Shutdown signal received ({}), stopping listeners...", signal);
            None
        }
        result = listeners.join_next() => {
            match result {
                Some(Ok(Ok(()))) => Some(anyhow::anyhow!("listener task exited unexpectedly")),
                Some(Ok(Err(err))) => Some(err),
                Some(Err(err)) => Some(anyhow::Error::new(err).context("listener task failed")),
                None => Some(anyhow::anyhow!("no listeners were started")),
            }
        }
    };

    let _ = shutdown_tx.send(true);

    while let Some(result) = listeners.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                if shutdown_error.is_none() {
                    shutdown_error = Some(err);
                }
            }
            Err(err) => {
                if shutdown_error.is_none() {
                    shutdown_error = Some(anyhow::Error::new(err).context("listener task failed"));
                }
            }
        }
    }

    if let Some(err) = shutdown_error {
        return Err(err);
    }

    Ok(())
}

async fn shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => "SIGINT",
            _ = terminate.recv() => "SIGTERM",
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install CTRL+C handler");
        "CTRL+C"
    }
}

async fn run_http_listener(
    bind: SocketAddr,
    router: Router,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind HTTP listener on {}", bind))?;

    axum::serve(listener, router)
        .with_graceful_shutdown(wait_for_shutdown(shutdown))
        .await
        .with_context(|| format!("HTTP listener on {} failed", bind))?;

    Ok(())
}

async fn run_https_listener(
    bind: SocketAddr,
    router: Router,
    tls_config: Arc<rustls::ServerConfig>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind HTTPS listener on {}", bind))?;
    let acceptor = TlsAcceptor::from(tls_config);

    loop {
        let accepted = tokio::select! {
            _ = shutdown.changed() => break,
            accepted = accept_connection(&listener) => accepted,
        };

        let Some((tcp_stream, remote_addr)) = accepted else {
            continue;
        };

        let acceptor = acceptor.clone();
        let service = router.clone().into_service::<Body>();
        tokio::spawn(async move {
            match acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    let hyper_service = TowerToHyperService::new(
                        service.map_request(|req: Request<Incoming>| req.map(Body::new)),
                    );

                    if let Err(err) = Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(TokioIo::new(tls_stream), hyper_service)
                        .await
                    {
                        error!("HTTPS connection {} failed: {}", remote_addr, err);
                    }
                }
                Err(err) => {
                    error!("TLS handshake failed for {}: {}", remote_addr, err);
                }
            }
        });
    }

    Ok(())
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    let _ = shutdown.changed().await;
}

async fn accept_connection(listener: &TcpListener) -> Option<(tokio::net::TcpStream, SocketAddr)> {
    match listener.accept().await {
        Ok(conn) => Some(conn),
        Err(err) => {
            if is_connection_error(&err) {
                return None;
            }

            error!("accept error: {}", err);
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            None
        }
    }
}

fn is_connection_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
    )
}

fn parse_optional_bind(bind: Option<&str>) -> anyhow::Result<Option<SocketAddr>> {
    bind.filter(|value| !value.trim().is_empty())
        .map(|value| value.parse().context("invalid local_bind"))
        .transpose()
}

fn listener_addresses_conflict(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port() && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
}

fn load_tls_server_config(
    tls_files: &ServerTlsConfig,
) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let certs = load_certificates(&tls_files.cert_path)?;
    let key = load_private_key(&tls_files.key_path)?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to build rustls server config")?;
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(tls_config))
}

fn load_certificates(path: &str) -> anyhow::Result<Vec<Certificate>> {
    let file = File::open(path).with_context(|| format!("failed to open TLS cert {}", path))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader).context("failed to parse TLS certificate")?;

    if certs.is_empty() {
        bail!("no certificates found in {}", path);
    }

    Ok(certs.into_iter().map(Certificate).collect())
}

fn load_private_key(path: &str) -> anyhow::Result<PrivateKey> {
    let file = File::open(path).with_context(|| format!("failed to open TLS key {}", path))?;
    let mut reader = BufReader::new(file);

    let mut pkcs8_keys =
        rustls_pemfile::pkcs8_private_keys(&mut reader).context("failed to parse PKCS#8 key")?;
    if let Some(key) = pkcs8_keys.pop() {
        return Ok(PrivateKey(key));
    }

    let file = File::open(path).with_context(|| format!("failed to reopen TLS key {}", path))?;
    let mut reader = BufReader::new(file);
    let mut rsa_keys =
        rustls_pemfile::rsa_private_keys(&mut reader).context("failed to parse RSA key")?;
    if let Some(key) = rsa_keys.pop() {
        return Ok(PrivateKey(key));
    }

    bail!("no supported private key found in {}", path)
}

async fn run_healthcheck() -> anyhow::Result<()> {
    let config = ServerConfig::load()?;
    let url = healthcheck_url(&config)?;

    let client = if url.starts_with("https://") {
        let tls_config = config
            .tls_config()?
            .context("HTTPS healthcheck requires tls_cert_path and tls_key_path")?;
        reqwest::Client::builder()
            .add_root_certificate(load_reqwest_certificate(&tls_config.cert_path)?)
            .build()
            .context("failed to build HTTPS healthcheck client")?
    } else {
        reqwest::Client::builder()
            .build()
            .context("failed to build healthcheck client")?
    };

    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to connect to {}", url))?;

    if !response.status().is_success() {
        bail!("unexpected healthcheck status {}", response.status());
    }

    let body: serde_json::Value = response
        .json()
        .await
        .context("failed to decode healthcheck JSON response")?;

    if body.get("status").and_then(|status| status.as_str()) == Some("ok") {
        return Ok(());
    }

    bail!("unexpected healthcheck response")
}

fn healthcheck_url(config: &ServerConfig) -> anyhow::Result<String> {
    if let Some(local_addr) = parse_optional_bind(config.local_bind.as_deref())? {
        let target = healthcheck_target(&local_addr.to_string())?;
        return Ok(format!("http://{}/api/v1/health", target));
    }

    if config.tls_config()?.is_some() {
        let addr: SocketAddr = config.bind.parse()?;
        if addr.ip().is_unspecified() {
            bail!(
                "HTTPS healthcheck requires BANNKENN_LOCAL_BIND or an explicit BANNKENN_BIND host that matches the certificate SAN"
            );
        }
        return Ok(format!("https://{}/api/v1/health", addr));
    }

    let target = healthcheck_target(&config.bind)?;
    Ok(format!("http://{}/api/v1/health", target))
}

fn load_reqwest_certificate(path: &str) -> anyhow::Result<reqwest::Certificate> {
    let bytes = std::fs::read(path).with_context(|| format!("failed to read TLS cert {}", path))?;
    reqwest::Certificate::from_pem(&bytes).context("failed to parse PEM certificate")
}

fn healthcheck_target(bind: &str) -> anyhow::Result<SocketAddr> {
    let addr: SocketAddr = bind.parse()?;
    let ip = match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };

    Ok(SocketAddr::new(ip, addr.port()))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_state_creation() {
        let config = ServerConfig::default();
        assert_eq!(config.bind, "0.0.0.0:3022");
    }

    #[test]
    fn healthcheck_target_uses_loopback_for_unspecified_bind() {
        let addr = healthcheck_target("0.0.0.0:3022").unwrap();
        assert_eq!(addr, "127.0.0.1:3022".parse().unwrap());
    }

    #[test]
    fn healthcheck_target_preserves_explicit_host() {
        let addr = healthcheck_target("192.168.1.10:4040").unwrap();
        assert_eq!(addr, "192.168.1.10:4040".parse().unwrap());
    }

    #[test]
    fn healthcheck_url_prefers_local_bind() {
        let config = ServerConfig {
            bind: "0.0.0.0:3022".to_string(),
            local_bind: Some("127.0.0.1:3023".to_string()),
            tls_cert_path: Some("/etc/bannkenn/tls/server.crt".to_string()),
            tls_key_path: Some("/etc/bannkenn/tls/server.key".to_string()),
            ..ServerConfig::default()
        };

        assert_eq!(
            healthcheck_url(&config).unwrap(),
            "http://127.0.0.1:3023/api/v1/health".to_string()
        );
    }

    #[test]
    fn healthcheck_url_uses_https_for_tls_bind() {
        let config = ServerConfig {
            bind: "198.51.100.24:3022".to_string(),
            tls_cert_path: Some("/etc/bannkenn/tls/server.crt".to_string()),
            tls_key_path: Some("/etc/bannkenn/tls/server.key".to_string()),
            ..ServerConfig::default()
        };

        assert_eq!(
            healthcheck_url(&config).unwrap(),
            "https://198.51.100.24:3022/api/v1/health".to_string()
        );
    }

    #[test]
    fn healthcheck_url_requires_local_bind_for_tls_with_unspecified_host() {
        let config = ServerConfig {
            bind: "0.0.0.0:3022".to_string(),
            tls_cert_path: Some("/etc/bannkenn/tls/server.crt".to_string()),
            tls_key_path: Some("/etc/bannkenn/tls/server.key".to_string()),
            ..ServerConfig::default()
        };

        assert!(healthcheck_url(&config).is_err());
    }

    #[test]
    fn listener_addresses_conflict_when_unspecified_host_reuses_port() {
        assert!(listener_addresses_conflict(
            "0.0.0.0:3022".parse().unwrap(),
            "127.0.0.1:3022".parse().unwrap()
        ));
    }

    #[test]
    fn listener_addresses_do_not_conflict_on_different_ports() {
        assert!(!listener_addresses_conflict(
            "0.0.0.0:3022".parse().unwrap(),
            "127.0.0.1:3023".parse().unwrap()
        ));
    }
}
