use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::client::ApiClient;
use crate::config::SyncState;
use crate::firewall::{block_ip, detect_backend};

/// Polling loop that incrementally pulls block decisions from the server
/// and applies them to the local firewall. Runs every 30 seconds.
/// Also populates `known_blocked_ips` so the watcher can detect already-listed IPs.
pub async fn sync_loop(client: ApiClient, known_blocked_ips: Arc<RwLock<HashMap<String, String>>>) {
    let state_path = match SyncState::state_path() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("sync_loop: cannot determine state path: {}", e);
            return;
        }
    };

    let mut state = SyncState::load(&state_path);
    let backend = detect_backend();
    let interval = Duration::from_secs(30);

    tracing::info!(
        "sync_loop started (last_synced_id={})",
        state.last_synced_id
    );

    loop {
        match client.fetch_decisions_since(state.last_synced_id).await {
            Ok(rows) => {
                if !rows.is_empty() {
                    tracing::info!("sync fetch: {} new decision(s)", rows.len());
                } else {
                    tracing::debug!(
                        "sync fetch: no new decisions since id={}",
                        state.last_synced_id
                    );
                }

                for row in &rows {
                    match block_ip(&row.ip, &backend).await {
                        Ok(_) => tracing::info!("sync: blocked IP {}", row.ip),
                        Err(e) => tracing::warn!("sync block failed for {}: {}", row.ip, e),
                    }
                    known_blocked_ips.write().await.insert(row.ip.clone(), row.source.clone());
                    state.last_synced_id = row.id;
                }

                if !rows.is_empty() {
                    if let Err(e) = state.save(&state_path) {
                        tracing::warn!("sync: failed to save state: {}", e);
                    }
                }
            }
            Err(e) => tracing::warn!("sync fetch failed: {}", e),
        }

        tokio::time::sleep(interval).await;
    }
}
