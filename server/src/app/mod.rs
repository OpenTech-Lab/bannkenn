mod healthcheck;
mod router;
mod runtime;

use crate::{behavior_pg::BehaviorPgArchive, config::ServerConfig, db::Db, feeds};
use std::sync::Arc;
use tracing::{error, info};

pub use healthcheck::{healthcheck_target, healthcheck_url, run_healthcheck};
pub use runtime::{listener_addresses_conflict, parse_optional_bind};

pub async fn main_entry() -> anyhow::Result<()> {
    if matches!(std::env::args().nth(1).as_deref(), Some("healthcheck")) {
        return run_healthcheck().await;
    }

    init_tracing();
    run_server().await
}

pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing_subscriber::filter::LevelFilter::INFO.into()),
        )
        .init();
}

pub async fn run_server() -> anyhow::Result<()> {
    info!("Starting BannKenn server...");

    let config = ServerConfig::load()?;
    info!(
        "Configuration loaded: bind={} local_bind={:?} tls_enabled={}",
        config.bind,
        config.local_bind,
        config.tls_config()?.is_some()
    );

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

    let db_for_backfill = db.clone();
    tokio::spawn(async move {
        match db_for_backfill.backfill_decision_geoip_unknowns().await {
            Ok(count) => info!("GeoIP backfill complete: {} decision rows updated", count),
            Err(err) => error!("GeoIP backfill failed: {}", err),
        }
    });

    feeds::start_feed_task(db.clone()).await;
    info!("Feed task started");

    let db_for_campaign = db.clone();
    tokio::spawn(async move {
        let interval = tokio::time::Duration::from_secs(60);
        info!("Campaign detection task started (interval=60s)");

        loop {
            tokio::time::sleep(interval).await;

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
                            Err(err) => {
                                error!("Failed to insert campaign decision for {}: {}", ip, err)
                            }
                        }
                    }
                }
                Ok(_) => {}
                Err(err) => error!("Campaign detection failed: {}", err),
            }
        }
    });

    let router = router::build_router(db.clone(), config.clone(), behavior_archive);
    let config = Arc::new(config);
    runtime::serve_router(router, config).await?;

    info!("Server shut down successfully");
    Ok(())
}
