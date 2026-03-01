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

pub async fn start_feed_task(db: Arc<Db>) {
    // Spawn a background task
    tokio::spawn(async move {
        // Run immediately on startup
        if let Err(e) = fetch_ipsum_feed(db.clone()).await {
            error!("Failed to fetch ipsum feed on startup: {}", e);
        }

        // Then run every 24 hours
        let mut interval = interval(Duration::from_secs(24 * 60 * 60));

        loop {
            interval.tick().await;
            if let Err(e) = fetch_ipsum_feed(db.clone()).await {
                error!("Failed to fetch ipsum feed: {}", e);
            }
        }
    });
}
