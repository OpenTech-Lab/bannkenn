use crate::db::Db;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{error, info};

pub async fn fetch_ipsum_feed(db: Arc<Db>) -> anyhow::Result<()> {
    info!("Fetching ipsum feed...");

    let response =
        reqwest::get("https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt").await?;

    let text = response.text().await?;

    for line in text.lines() {
        // Parse lines as <ip>\t<count>
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 2 {
            if let Ok(count) = parts[1].trim().parse::<i32>() {
                if count >= 3 {
                    let ip = parts[0].trim();
                    match db
                        .insert_decision(ip, "ipsum_feed", "block", "ipsum_feed")
                        .await
                    {
                        Ok(_) => {
                            // Successfully inserted
                        }
                        Err(e) => {
                            // Log but continue processing other IPs
                            error!("Failed to insert decision for IP {}: {}", ip, e);
                        }
                    }
                }
            }
        }
    }

    info!("Ipsum feed fetch completed");
    Ok(())
}

/// Fetch a FireHOL netset feed and insert all non-comment entries into the DB.
/// Lines starting with '#' are comments; all other non-empty lines are IPs or CIDRs.
async fn fetch_firehol_feed(db: Arc<Db>, url: &str, source: &str) -> anyhow::Result<()> {
    info!("Fetching FireHOL feed: {}", source);

    let response = reqwest::get(url).await?;
    let text = response.text().await?;

    for line in text.lines() {
        let entry = line.trim();
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }
        match db.insert_decision(entry, source, "block", source).await {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to insert decision for {}: {}", entry, e);
            }
        }
    }

    info!("FireHOL feed fetch completed: {}", source);
    Ok(())
}

pub async fn start_feed_task(db: Arc<Db>) {
    // Spawn a background task
    tokio::spawn(async move {
        // Run all feeds immediately on startup
        if let Err(e) = fetch_ipsum_feed(db.clone()).await {
            error!("Failed to fetch ipsum feed on startup: {}", e);
        }
        if let Err(e) = fetch_firehol_feed(
            db.clone(),
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
            "firehol_level1",
        )
        .await
        {
            error!("Failed to fetch FireHOL level1 feed on startup: {}", e);
        }
        if let Err(e) = fetch_firehol_feed(
            db.clone(),
            "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
            "firehol_level2",
        )
        .await
        {
            error!("Failed to fetch FireHOL level2 feed on startup: {}", e);
        }

        // Then run every 24 hours
        let mut ticker = interval(Duration::from_secs(24 * 60 * 60));

        loop {
            ticker.tick().await;
            if let Err(e) = fetch_ipsum_feed(db.clone()).await {
                error!("Failed to fetch ipsum feed: {}", e);
            }
            if let Err(e) = fetch_firehol_feed(
                db.clone(),
                "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
                "firehol_level1",
            )
            .await
            {
                error!("Failed to fetch FireHOL level1 feed: {}", e);
            }
            if let Err(e) = fetch_firehol_feed(
                db.clone(),
                "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
                "firehol_level2",
            )
            .await
            {
                error!("Failed to fetch FireHOL level2 feed: {}", e);
            }
        }
    });
}
