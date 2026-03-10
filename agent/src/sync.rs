use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::client::ApiClient;
use crate::config::{OfflineAgentState, SyncState};
use crate::firewall::{block_ip, detect_backend, should_skip_local_firewall_enforcement};
use crate::shared_risk::SharedRiskSnapshot;
use crate::watcher::BlockOutcome;

pub async fn persist_offline_state(
    known_blocked_ips: &Arc<RwLock<HashMap<String, String>>>,
    shared_risk_snapshot: &Arc<RwLock<SharedRiskSnapshot>>,
) {
    let path = match OfflineAgentState::state_path() {
        Ok(path) => path,
        Err(err) => {
            tracing::warn!("offline-state: cannot determine state path: {}", err);
            return;
        }
    };

    let state = OfflineAgentState {
        known_blocked_ips: known_blocked_ips.read().await.clone(),
        shared_risk_snapshot: shared_risk_snapshot.read().await.clone(),
    };

    if let Err(err) = state.save(&path) {
        tracing::warn!("offline-state: failed to save cache: {}", err);
    }
}

/// Polling loop that incrementally pulls block decisions from the server
/// and applies them to the local firewall. Runs every 30 seconds.
/// Also populates `known_blocked_ips` so the watcher can detect already-listed IPs.
pub async fn sync_loop(
    client: ApiClient,
    known_blocked_ips: Arc<RwLock<HashMap<String, String>>>,
    enforced_blocked_ips: Arc<RwLock<HashSet<String>>>,
    shared_risk_snapshot: Arc<RwLock<SharedRiskSnapshot>>,
    block_outcome_tx: tokio::sync::mpsc::Sender<BlockOutcome>,
) {
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
                    if should_skip_local_firewall_enforcement(&row.ip) {
                        tracing::warn!(
                            "sync: skipping firewall enforcement for local/reserved address {}",
                            row.ip
                        );
                        known_blocked_ips
                            .write()
                            .await
                            .insert(row.ip.clone(), row.source.clone());
                        state.last_synced_id = row.id;
                        continue;
                    }

                    match block_ip(&row.ip, &backend).await {
                        Ok(_) => {
                            tracing::info!("sync: blocked IP {}", row.ip);
                            enforced_blocked_ips.write().await.insert(row.ip.clone());
                            let _ = block_outcome_tx
                                .send(BlockOutcome::Enforced(row.ip.clone()))
                                .await;
                        }
                        Err(e) => tracing::warn!("sync block failed for {}: {}", row.ip, e),
                    }
                    known_blocked_ips
                        .write()
                        .await
                        .insert(row.ip.clone(), row.source.clone());
                    state.last_synced_id = row.id;
                }

                if !rows.is_empty() {
                    if let Err(e) = state.save(&state_path) {
                        tracing::warn!("sync: failed to save state: {}", e);
                    }
                    persist_offline_state(&known_blocked_ips, &shared_risk_snapshot).await;
                }
            }
            Err(e) => tracing::warn!("sync fetch failed: {}", e),
        }

        match client.fetch_shared_risk_profile().await {
            Ok(profile) => {
                *shared_risk_snapshot.write().await = profile;
                persist_offline_state(&known_blocked_ips, &shared_risk_snapshot).await;
            }
            Err(e) => tracing::warn!("shared-risk fetch failed: {}", e),
        }

        tokio::time::sleep(interval).await;
    }
}
