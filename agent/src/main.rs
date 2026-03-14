mod burst;
mod butterfly;
mod campaign;
mod client;
mod config;
mod containment;
mod correlator;
mod ebpf;
mod enforcement;
mod event_risk;
mod firewall;
mod geoip;
mod outbox;
mod patterns;
mod reporting;
mod risk_level;
mod scorer;
mod service;
mod shared_risk;
mod sync;
mod tofu;
mod updater;
mod watcher;

use anyhow::Result;
use clap::{Parser, Subcommand};
use reqwest::{Certificate, Method, StatusCode, Url};
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, Notify, RwLock};
use tokio::time::{interval, Duration};
use uuid::Uuid;

use crate::client::{build_http_client, ApiClient};
use crate::config::{
    default_runtime_campaign_config, default_runtime_containment_config, AgentConfig,
    ContainmentConfig, OfflineAgentState,
};
use crate::containment::{ContainmentDecision, ContainmentRuntime, CONTAINMENT_TICK_INTERVAL_SECS};
use crate::ebpf::events::{BehaviorEvent, BehaviorLevel};
use crate::ebpf::SensorManager;
use crate::firewall::{
    allow_ip, cleanup_firewall, detect_backend, effective_block_patterns, init_firewall,
    is_block_pattern_effectively_enforced, pattern_set_covers_pattern, pattern_set_matches_ip,
    reconcile_block_patterns, reconcile_whitelist_ips, should_skip_local_firewall_enforcement,
    unblock_ip,
};
use crate::outbox::{flush_pending, Outbox, OutboxPayload};
use crate::service::{install_systemd_unit, uninstall_systemd_unit, SERVICE_UNIT_PATH};
use crate::shared_risk::SharedRiskSnapshot;
use crate::tofu::{fetch_presented_certificate, save_presented_certificate};
use crate::watcher::{watch, BlockOutcome, SecurityEvent};

const OPERATOR_ACTION_POLL_INTERVAL_SECS: u64 = 10;

#[derive(Parser)]
#[command(name = "bannkenn-agent")]
#[command(about = "BannKenn Agent - Intrusion Prevention System", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the agent
    Run,
    /// Remove BannKenn-managed firewall state and exit
    CleanupFirewall,
    /// Initialize local configuration and register with the dashboard if reachable
    Init,
    /// Stop, disable, and remove the systemd service plus local agent state
    Uninstall,
    /// Register or refresh this agent with the BannKenn server API
    Connect,
    /// Diagnose DNS, TCP, TLS, and heartbeat connectivity to the configured BannKenn server
    #[command(name = "connecttest", visible_alias = "connect-test")]
    ConnectTest,
    /// Download and install the latest released agent binary, or a specific version
    Update {
        /// Optional version such as 1.3.18 or v1.3.18; defaults to latest release
        version: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
struct RegisterAgentResponse {
    token: String,
}

fn desired_firewall_patterns(
    known_blocked_ips: &HashMap<String, String>,
    whitelisted_ips: &HashSet<String>,
) -> (Vec<String>, usize, usize, usize) {
    let mut candidates = Vec::new();
    let mut skipped_local = 0usize;
    let mut skipped_whitelist = 0usize;

    for pattern in known_blocked_ips.keys() {
        if pattern_set_covers_pattern(whitelisted_ips, pattern) {
            skipped_whitelist += 1;
            continue;
        }
        if should_skip_local_firewall_enforcement(pattern) {
            skipped_local += 1;
            continue;
        }
        candidates.push(pattern.as_str());
    }

    let effective = effective_block_patterns(candidates);
    let collapsed_overlaps = known_blocked_ips
        .len()
        .saturating_sub(skipped_local + skipped_whitelist + effective.len());

    (
        effective,
        skipped_local,
        skipped_whitelist,
        collapsed_overlaps,
    )
}

fn desired_whitelist_patterns(whitelisted_ips: &HashSet<String>) -> Vec<String> {
    effective_block_patterns(whitelisted_ips.iter().map(String::as_str))
}

async fn ensure_whitelisted_ip_override(
    ip: &str,
    backend: &firewall::FirewallBackend,
    enforced_whitelisted_ips: &Arc<RwLock<HashSet<String>>>,
    enforced_blocked_ips: &Arc<RwLock<HashSet<String>>>,
) {
    if let Err(e) = allow_ip(ip, backend).await {
        tracing::warn!("Failed to ensure whitelisted IP {} is allowed: {}", ip, e);
    } else {
        enforced_whitelisted_ips
            .write()
            .await
            .insert(ip.to_string());
    }

    if let Err(e) = unblock_ip(ip, backend).await {
        tracing::warn!(
            "Failed to remove exact local block for whitelisted IP {}: {}",
            ip,
            e
        );
    } else {
        enforced_blocked_ips.write().await.remove(ip);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Init) => init().await?,
        Some(Commands::Uninstall) => uninstall().await?,
        Some(Commands::Connect) => connect().await?,
        Some(Commands::ConnectTest) => connect_test().await?,
        Some(Commands::CleanupFirewall) => cleanup_firewall_command().await?,
        Some(Commands::Update { version }) => updater::update(version.as_deref()).await?,
        Some(Commands::Run) | None => run().await?,
    }

    Ok(())
}

/// Run the agent
async fn run() -> Result<()> {
    tracing::info!("Starting BannKenn Agent");

    let config = AgentConfig::load()?;

    if config.server_url.is_empty() || config.jwt_token.is_empty() {
        tracing::error!(
            "Configuration incomplete. Run 'bannkenn-agent init' to configure/register, or 'bannkenn-agent connect' to retry registration"
        );
        return Err(anyhow::anyhow!(
            "Configuration incomplete. Run 'bannkenn-agent init' to configure/register, or 'bannkenn-agent connect' to retry registration"
        ));
    }

    tracing::info!("Configured to connect to: {}", config.server_url);
    let monitored_paths = config.effective_log_paths();
    tracing::info!("Monitoring {} log path(s)", monitored_paths.len());
    for path in &monitored_paths {
        tracing::info!("  - {}", path);
    }
    tracing::info!(
        "Threshold: {} attempts in {} seconds",
        config.threshold,
        config.window_secs
    );
    if let Some(containment) = config.containment.as_ref() {
        if containment.enabled {
            tracing::info!(
                "Containment sensor enabled (dry_run={}, watch_paths={}, poll_interval_ms={})",
                containment.dry_run,
                containment.watch_paths.len(),
                containment.poll_interval_ms.max(100)
            );
            if containment.watch_paths.is_empty() {
                tracing::warn!(
                    "Containment is enabled but no watch_paths are configured; behavior sensing will stay idle"
                );
            }
        } else {
            tracing::info!("Containment behavior monitoring disabled");
        }
    }

    // Initialise GeoIP resolver if an mmdb directory is configured.
    // This is optional — if absent, country/ASN features degrade to "Unknown".
    if let Some(ref dir) = config.mmdb_dir {
        geoip::init(dir);
    } else {
        tracing::info!(
            "mmdb_dir not configured — GeoIP features disabled (country/ASN will show Unknown)"
        );
    }

    let backend = detect_backend();
    tracing::info!("Detected firewall backend: {:?}", backend);

    // Ensure required firewall infrastructure exists
    // (nftables: creates the dedicated BannKenn table, set, and drop rules).
    if let Err(e) = init_firewall(&backend).await {
        tracing::error!(
            "Failed to initialize firewall infrastructure: {}. IP blocking will not work.",
            e
        );
    }

    let api_client = ApiClient::new(
        config.server_url.clone(),
        config.jwt_token.clone(),
        config.ca_cert_path.clone(),
    )?;
    let offline_state_path = OfflineAgentState::state_path()?;
    let offline_state = OfflineAgentState::load(&offline_state_path);

    // Shared set of IPs already present in the server's block list DB.
    // Pre-populated at startup; kept in sync by sync_loop.
    // Maps IP → source name (e.g. "ipsum_feed", "agent") so that watcher can
    // report which database listed the IP when emitting level=listed events.
    let known_blocked_ips: Arc<RwLock<HashMap<String, String>>> =
        Arc::new(RwLock::new(offline_state.known_blocked_ips.clone()));
    let enforced_blocked_ips: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));
    let enforced_whitelisted_ips: Arc<RwLock<HashSet<String>>> =
        Arc::new(RwLock::new(HashSet::new()));
    let whitelisted_ips: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(
        offline_state.whitelisted_ips.iter().cloned().collect(),
    ));
    let shared_risk_snapshot: Arc<RwLock<SharedRiskSnapshot>> =
        Arc::new(RwLock::new(offline_state.shared_risk_snapshot.clone()));

    {
        let whitelist_snapshot = whitelisted_ips.read().await.clone();
        let desired_whitelist_patterns = desired_whitelist_patterns(&whitelist_snapshot);
        let whitelist_summary = reconcile_whitelist_ips(
            &desired_whitelist_patterns,
            &enforced_whitelisted_ips,
            &backend,
        )
        .await;
        if !whitelist_snapshot.is_empty() {
            known_blocked_ips
                .write()
                .await
                .retain(|ip, _| !pattern_set_covers_pattern(&whitelist_snapshot, ip));
            tracing::info!(
                "Loaded {} whitelisted IP(s) from offline cache ({} firewall allow(s) added, {} removed, {} add failures, {} remove failures)",
                whitelist_snapshot.len(),
                whitelist_summary.added,
                whitelist_summary.removed,
                whitelist_summary.add_failed,
                whitelist_summary.remove_failed
            );
        }
    }

    let init_client = ApiClient::new(
        config.server_url.clone(),
        config.jwt_token.clone(),
        config.ca_cert_path.clone(),
    )?;
    match init_client.fetch_whitelist().await {
        Ok(entries) => {
            sync::apply_whitelist_snapshot(
                entries,
                &known_blocked_ips,
                &enforced_blocked_ips,
                &enforced_whitelisted_ips,
                &whitelisted_ips,
                &shared_risk_snapshot,
                &backend,
            )
            .await;
        }
        Err(e) => tracing::warn!("Failed to load initial whitelist: {}", e),
    }

    if !offline_state.known_blocked_ips.is_empty() {
        let whitelist_snapshot = whitelisted_ips.read().await.clone();
        let (desired_patterns, skipped_local, skipped_whitelist, collapsed_overlaps) = {
            let known = known_blocked_ips.read().await;
            desired_firewall_patterns(&known, &whitelist_snapshot)
        };
        let summary =
            reconcile_block_patterns(&desired_patterns, &enforced_blocked_ips, &backend).await;
        tracing::info!(
            "Loaded cached offline state: {} blocked pattern(s), shared-risk categories={}; reconciled firewall to {} effective pattern(s) ({} added, {} removed, {} add failures, {} remove failures, {} skipped local/reserved, {} skipped whitelisted, {} collapsed overlaps)",
            offline_state.known_blocked_ips.len(),
            offline_state.shared_risk_snapshot.categories.len(),
            desired_patterns.len(),
            summary.added,
            summary.removed,
            summary.add_failed,
            summary.remove_failed,
            skipped_local,
            skipped_whitelist,
            collapsed_overlaps
        );
    }

    // Initial fetch: load all existing block-list IPs before starting the watcher
    // so detections are classified "listed" from the very first event.
    // Also re-applies firewall rules so blocks survive agent/host restarts.
    match init_client.fetch_decisions_since(0).await {
        Ok(decisions) => {
            let whitelist_snapshot = whitelisted_ips.read().await.clone();
            {
                let mut set = known_blocked_ips.write().await;
                for d in &decisions {
                    if pattern_set_covers_pattern(&whitelist_snapshot, &d.ip) {
                        continue;
                    }
                    set.insert(d.ip.clone(), d.source.clone());
                }
            }
            let (desired_patterns, skipped_local, skipped_whitelist, collapsed_overlaps) = {
                let known = known_blocked_ips.read().await;
                desired_firewall_patterns(&known, &whitelist_snapshot)
            };
            let summary =
                reconcile_block_patterns(&desired_patterns, &enforced_blocked_ips, &backend).await;
            tracing::info!(
                "Loaded {} known blocked pattern(s) from server; reconciled firewall to {} effective pattern(s) ({} added, {} removed, {} add failures, {} remove failures, {} skipped local/reserved, {} skipped whitelisted, {} collapsed overlaps)",
                decisions.len(),
                desired_patterns.len(),
                summary.added,
                summary.removed,
                summary.add_failed,
                summary.remove_failed,
                skipped_local,
                skipped_whitelist,
                collapsed_overlaps
            );
            sync::persist_offline_state(
                &known_blocked_ips,
                &whitelisted_ips,
                &shared_risk_snapshot,
            )
            .await;
        }
        Err(e) => tracing::warn!("Failed to load initial block list: {}", e),
    }

    match init_client.fetch_shared_risk_profile().await {
        Ok(profile) => {
            *shared_risk_snapshot.write().await = profile;
            sync::persist_offline_state(
                &known_blocked_ips,
                &whitelisted_ips,
                &shared_risk_snapshot,
            )
            .await;
        }
        Err(e) => tracing::warn!("Failed to load initial shared-risk profile: {}", e),
    }

    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(1000);
    let (behavior_tx, mut behavior_rx) = mpsc::channel::<BehaviorEvent>(256);
    let (block_outcome_tx, block_outcome_rx) = mpsc::channel::<BlockOutcome>(1000);
    let outbox = Arc::new(Mutex::new(Outbox::load_default()?));
    let outbox_notify = Arc::new(Notify::new());

    let config_arc = Arc::new(config);
    let containment_runtime = ContainmentRuntime::from_agent_config(config_arc.as_ref());
    let mut containment_tick = containment_runtime
        .as_ref()
        .map(|_| interval(Duration::from_secs(CONTAINMENT_TICK_INTERVAL_SECS)));
    if let Some(ticker) = containment_tick.as_mut() {
        ticker.tick().await;
    }
    let operator_action_client = ApiClient::new(
        config_arc.server_url.clone(),
        config_arc.jwt_token.clone(),
        config_arc.ca_cert_path.clone(),
    )?;
    let mut operator_action_tick =
        interval(Duration::from_secs(OPERATOR_ACTION_POLL_INTERVAL_SECS));
    operator_action_tick.tick().await;

    let config_for_watcher = Arc::clone(&config_arc);
    let known_ips_for_watcher = Arc::clone(&known_blocked_ips);
    let enforced_ips_for_watcher = Arc::clone(&enforced_blocked_ips);
    let whitelisted_ips_for_watcher = Arc::clone(&whitelisted_ips);
    let shared_risk_for_watcher = Arc::clone(&shared_risk_snapshot);
    let watcher_handle = tokio::spawn(async move {
        if let Err(e) = watch(
            config_for_watcher,
            tx,
            known_ips_for_watcher,
            enforced_ips_for_watcher,
            whitelisted_ips_for_watcher,
            shared_risk_for_watcher,
            block_outcome_rx,
        )
        .await
        {
            tracing::error!("Watcher error: {}", e);
        }
    });

    let behavior_handle = if let Some(manager) = config_arc
        .containment
        .as_ref()
        .and_then(SensorManager::from_config)
    {
        Some(tokio::spawn(async move {
            if let Err(e) = manager.run(behavior_tx).await {
                tracing::error!("Behavior sensor error: {}", e);
            }
        }))
    } else {
        drop(behavior_tx);
        None
    };

    let sync_client = ApiClient::new(
        config_arc.server_url.clone(),
        config_arc.jwt_token.clone(),
        config_arc.ca_cert_path.clone(),
    )?;
    let sync_handle = tokio::spawn(sync::sync_loop(
        sync_client,
        Arc::clone(&known_blocked_ips),
        Arc::clone(&enforced_blocked_ips),
        Arc::clone(&enforced_whitelisted_ips),
        Arc::clone(&whitelisted_ips),
        Arc::clone(&shared_risk_snapshot),
        block_outcome_tx.clone(),
    ));

    {
        let outbox = outbox.lock().await;
        if !outbox.is_empty() {
            let pending = outbox.len();
            tracing::info!("Loaded {} pending outbound report(s) from disk", pending);
        }
    }

    let flush_client = api_client.clone();
    let flush_outbox = Arc::clone(&outbox);
    let flush_notify = Arc::clone(&outbox_notify);
    let flush_handle = tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = flush_notify.notified() => {}
            }

            match flush_pending(&flush_client, &flush_outbox, 200).await {
                Ok(sent) if sent > 0 => {
                    tracing::info!("Flushed {} queued outbound report(s)", sent)
                }
                Ok(_) => {}
                Err(e) => tracing::warn!("Outbox flush failed: {}", e),
            }
        }
    });

    let heartbeat_client = ApiClient::new(
        config_arc.server_url.clone(),
        config_arc.jwt_token.clone(),
        config_arc.ca_cert_path.clone(),
    )?;
    let butterfly_enabled = config_arc.butterfly_shield.as_ref().map(|c| c.enabled);
    let heartbeat_handle = tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(30));
        ticker.tick().await;

        loop {
            match heartbeat_client.send_heartbeat(butterfly_enabled).await {
                Ok(_) => tracing::debug!("Heartbeat sent"),
                Err(e) => tracing::warn!("Failed to send heartbeat: {}", e),
            }

            ticker.tick().await;
        }
    });

    let mut shutdown_reason = None;
    let mut behavior_channel_open = behavior_handle.is_some();
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        let event = tokio::select! {
            maybe_event = rx.recv() => match maybe_event {
                Some(event) => Some(event),
                None => break,
            },
            maybe_behavior = behavior_rx.recv(), if behavior_channel_open => {
                match maybe_behavior {
                    Some(event) => {
                        log_behavior_event(&event, config_arc.containment.as_ref());
                        enqueue_outbox(
                            &outbox,
                            OutboxPayload::from_behavior_event(&event),
                            &outbox_notify,
                        )
                        .await;
                        if let Some(runtime) = containment_runtime.as_ref() {
                            match runtime.handle_event(&event).await {
                                Ok(Some(decision)) => {
                                    log_containment_decision(&decision);
                                    if let Some(payload) =
                                        OutboxPayload::from_containment_decision(&decision)
                                    {
                                        enqueue_outbox(&outbox, payload, &outbox_notify).await;
                                    }
                                }
                                Ok(None) => {}
                                Err(error) => tracing::warn!(
                                    "Containment runtime failed for behavior event pid={} score={}: {}",
                                    event.pid
                                        .map(|pid| pid.to_string())
                                        .unwrap_or_else(|| "unknown".to_string()),
                                    event.score,
                                    error
                                ),
                            }
                        }
                        None
                    }
                    None => {
                        behavior_channel_open = false;
                        None
                    }
                }
            }
            _ = async {
                if let Some(ticker) = containment_tick.as_mut() {
                    ticker.tick().await;
                }
            }, if containment_runtime.is_some() => {
                if let Some(runtime) = containment_runtime.as_ref() {
                    match runtime.tick().await {
                        Ok(Some(decision)) => {
                            log_containment_decision(&decision);
                            if let Some(payload) =
                                OutboxPayload::from_containment_decision(&decision)
                            {
                                enqueue_outbox(&outbox, payload, &outbox_notify).await;
                            }
                        }
                        Ok(None) => {}
                        Err(error) => tracing::warn!("Containment timer tick failed: {}", error),
                    }
                }
                None
            }
            _ = operator_action_tick.tick() => {
                if let Err(error) = poll_operator_containment_actions(
                    &operator_action_client,
                    containment_runtime.as_ref(),
                    &outbox,
                    &outbox_notify,
                ).await {
                    tracing::warn!("Operator containment action poll failed: {}", error);
                }
                None
            }
            reason = &mut shutdown => {
                shutdown_reason = Some(reason);
                break;
            }
        };
        let Some(event) = event else {
            continue;
        };

        tracing::info!(
            "Security event: IP={} level={} rank={} campaign={} attempts={}/{} at={}",
            event.ip,
            event.level,
            event.risk_rank,
            event.campaign.as_deref().unwrap_or("none"),
            event.attempts,
            event.effective_threshold,
            event.timestamp
        );
        let event_timestamp = event.timestamp.to_rfc3339();

        match event.level.as_str() {
            "ssh_access" => {
                // Successful SSH login — report to server for dashboard notification.
                // No firewall action. Persist first so it can be retried if the server is down.
                let username = event.username.as_deref().unwrap_or("unknown");
                tracing::info!(
                    "SSH access: user={} from={} log={}",
                    username,
                    event.ip,
                    event.log_path
                );
                enqueue_outbox(
                    &outbox,
                    OutboxPayload::SshLogin {
                        ip: event.ip.clone(),
                        username: username.to_string(),
                        timestamp: Some(event_timestamp.clone()),
                    },
                    &outbox_notify,
                )
                .await;
            }
            "block" => {
                // Apply firewall IMMEDIATELY — before any network I/O.
                let is_whitelisted = {
                    let whitelist_snapshot = whitelisted_ips.read().await;
                    pattern_set_matches_ip(&whitelist_snapshot, &event.ip)
                };
                if is_whitelisted {
                    tracing::info!("Skipping block event for whitelisted IP {}", event.ip);
                    let _ = block_outcome_tx
                        .send(BlockOutcome::Failed(event.ip.clone()))
                        .await;
                    ensure_whitelisted_ip_override(
                        &event.ip,
                        &backend,
                        &enforced_whitelisted_ips,
                        &enforced_blocked_ips,
                    )
                    .await;
                    continue;
                }

                if should_skip_local_firewall_enforcement(&event.ip) {
                    tracing::warn!(
                        "Skipping local/reserved block event for {} and leaving firewall unchanged",
                        event.ip
                    );
                    let _ = block_outcome_tx
                        .send(BlockOutcome::Failed(event.ip.clone()))
                        .await;
                    continue;
                }

                known_blocked_ips
                    .write()
                    .await
                    .insert(event.ip.clone(), "agent".to_string());
                let whitelist_snapshot = whitelisted_ips.read().await.clone();
                let desired_patterns = {
                    let known = known_blocked_ips.read().await;
                    desired_firewall_patterns(&known, &whitelist_snapshot).0
                };
                let summary =
                    reconcile_block_patterns(&desired_patterns, &enforced_blocked_ips, &backend)
                        .await;
                let enforced_snapshot = enforced_blocked_ips.read().await.clone();
                if is_block_pattern_effectively_enforced(&event.ip, &enforced_snapshot) {
                    tracing::info!("Blocked IP: {}", event.ip);
                    let _ = block_outcome_tx
                        .send(BlockOutcome::Enforced(event.ip.clone()))
                        .await;
                } else {
                    tracing::error!(
                        "Failed to block IP {} after reconcile ({} added, {} removed, {} add failures, {} remove failures)",
                        event.ip,
                        summary.added,
                        summary.removed,
                        summary.add_failed,
                        summary.remove_failed
                    );
                    let _ = block_outcome_tx
                        .send(BlockOutcome::Failed(event.ip.clone()))
                        .await;
                }
                // Update shared set so watcher won't re-process this IP.
                sync::persist_offline_state(
                    &known_blocked_ips,
                    &whitelisted_ips,
                    &shared_risk_snapshot,
                )
                .await;
                enqueue_outbox(
                    &outbox,
                    OutboxPayload::Decision {
                        ip: event.ip.clone(),
                        reason: event.reason.clone(),
                        timestamp: Some(event_timestamp.clone()),
                    },
                    &outbox_notify,
                )
                .await;
                enqueue_outbox(
                    &outbox,
                    OutboxPayload::Telemetry {
                        ip: event.ip.clone(),
                        reason: event.reason.clone(),
                        level: event.level.clone(),
                        log_path: Some(event.log_path.clone()),
                        timestamp: Some(event_timestamp.clone()),
                    },
                    &outbox_notify,
                )
                .await;
            }
            "listed" => {
                // IP already in block list DB: apply firewall IMMEDIATELY.
                let is_whitelisted = {
                    let whitelist_snapshot = whitelisted_ips.read().await;
                    pattern_set_matches_ip(&whitelist_snapshot, &event.ip)
                };
                if is_whitelisted {
                    tracing::info!("Skipping listed event for whitelisted IP {}", event.ip);
                    let _ = block_outcome_tx
                        .send(BlockOutcome::Failed(event.ip.clone()))
                        .await;
                    ensure_whitelisted_ip_override(
                        &event.ip,
                        &backend,
                        &enforced_whitelisted_ips,
                        &enforced_blocked_ips,
                    )
                    .await;
                    continue;
                }

                if should_skip_local_firewall_enforcement(&event.ip) {
                    tracing::warn!(
                        "Skipping local/reserved listed IP {} and leaving firewall unchanged",
                        event.ip
                    );
                    let _ = block_outcome_tx
                        .send(BlockOutcome::Failed(event.ip.clone()))
                        .await;
                    continue;
                }

                let whitelist_snapshot = whitelisted_ips.read().await.clone();
                let desired_patterns = {
                    let known = known_blocked_ips.read().await;
                    desired_firewall_patterns(&known, &whitelist_snapshot).0
                };
                let summary =
                    reconcile_block_patterns(&desired_patterns, &enforced_blocked_ips, &backend)
                        .await;
                let enforced_snapshot = enforced_blocked_ips.read().await.clone();
                if is_block_pattern_effectively_enforced(&event.ip, &enforced_snapshot) {
                    tracing::info!("Listed IP blocked by firewall: {}", event.ip);
                    let _ = block_outcome_tx
                        .send(BlockOutcome::Enforced(event.ip.clone()))
                        .await;
                } else {
                    tracing::error!(
                        "Failed to block listed IP {} after reconcile ({} added, {} removed, {} add failures, {} remove failures)",
                        event.ip,
                        summary.added,
                        summary.removed,
                        summary.add_failed,
                        summary.remove_failed
                    );
                    let _ = block_outcome_tx
                        .send(BlockOutcome::Failed(event.ip.clone()))
                        .await;
                }
                enqueue_outbox(
                    &outbox,
                    OutboxPayload::Telemetry {
                        ip: event.ip.clone(),
                        reason: event.reason.clone(),
                        level: event.level.clone(),
                        log_path: Some(event.log_path.clone()),
                        timestamp: Some(event_timestamp.clone()),
                    },
                    &outbox_notify,
                )
                .await;
            }
            _ => {
                enqueue_outbox(
                    &outbox,
                    OutboxPayload::Telemetry {
                        ip: event.ip.clone(),
                        reason: event.reason.clone(),
                        level: event.level.clone(),
                        log_path: Some(event.log_path.clone()),
                        timestamp: Some(event_timestamp.clone()),
                    },
                    &outbox_notify,
                )
                .await;
            }
        }
    }

    watcher_handle.abort();
    if let Some(handle) = &behavior_handle {
        handle.abort();
    }
    sync_handle.abort();
    flush_handle.abort();
    heartbeat_handle.abort();

    let _ = watcher_handle.await;
    if let Some(handle) = behavior_handle {
        let _ = handle.await;
    }
    let _ = sync_handle.await;
    let _ = flush_handle.await;
    let _ = heartbeat_handle.await;

    if let Some(reason) = shutdown_reason {
        tracing::info!(
            "Shutdown signal received ({}); removing BannKenn firewall state",
            reason
        );
        if let Err(e) = cleanup_firewall(&backend).await {
            tracing::error!("Failed to clean up firewall state during shutdown: {}", e);
        }
    }

    Ok(())
}

async fn enqueue_outbox(outbox: &Arc<Mutex<Outbox>>, payload: OutboxPayload, notify: &Arc<Notify>) {
    let enqueue_result = {
        let mut outbox = outbox.lock().await;
        outbox.enqueue(payload)
    };

    match enqueue_result {
        Ok(_) => notify.notify_one(),
        Err(e) => tracing::warn!("Failed to persist outbound report: {}", e),
    }
}

async fn poll_operator_containment_actions(
    client: &ApiClient,
    containment_runtime: Option<&ContainmentRuntime>,
    outbox: &Arc<Mutex<Outbox>>,
    notify: &Arc<Notify>,
) -> Result<()> {
    let actions = client.fetch_pending_containment_actions(20).await?;
    if actions.is_empty() {
        return Ok(());
    }

    tracing::info!(
        "Processing {} pending operator containment action(s)",
        actions.len()
    );

    for action in actions {
        let executed_at = chrono::Utc::now().to_rfc3339();

        let result = if let Some(runtime) = containment_runtime {
            match runtime.apply_operator_action(&action).await {
                Ok(result) => result,
                Err(error) => {
                    let message = format!("failed to apply operator action: {}", error);
                    client
                        .acknowledge_containment_action(
                            action.id,
                            "failed",
                            None,
                            &message,
                            &executed_at,
                        )
                        .await?;
                    tracing::warn!(
                        "Operator containment action {} failed for agent {}: {}",
                        action.id,
                        action.agent_name,
                        error
                    );
                    continue;
                }
            }
        } else {
            let message = "containment runtime is disabled on this agent".to_string();
            client
                .acknowledge_containment_action(action.id, "failed", None, &message, &executed_at)
                .await?;
            tracing::warn!(
                "Operator containment action {} ignored because containment is disabled",
                action.id
            );
            continue;
        };

        if let Some(decision) = result.decision.as_ref() {
            log_containment_decision(decision);
            if let Some(payload) = OutboxPayload::from_containment_decision(decision) {
                enqueue_outbox(outbox, payload, notify).await;
            }
        }

        let status = if result.applied { "applied" } else { "failed" };
        let resulting_state = result
            .decision
            .as_ref()
            .map(|decision| decision.state.as_str());
        client
            .acknowledge_containment_action(
                action.id,
                status,
                resulting_state,
                &result.message,
                &executed_at,
            )
            .await?;
    }

    Ok(())
}

fn log_behavior_event(event: &BehaviorEvent, containment: Option<&ContainmentConfig>) {
    let process = event
        .exe_path
        .as_deref()
        .or(event.process_name.as_deref())
        .unwrap_or("unknown");
    let reasons = if event.reasons.is_empty() {
        "none".to_string()
    } else {
        event.reasons.join(", ")
    };
    let enforcement_mode = match event.level {
        BehaviorLevel::Observed | BehaviorLevel::Suspicious => "observe-only",
        BehaviorLevel::ThrottleCandidate => {
            if containment
                .map(|cfg| cfg.throttle_enabled && !cfg.dry_run)
                .unwrap_or(false)
            {
                "throttle-active"
            } else {
                "dry-run throttle candidate"
            }
        }
        BehaviorLevel::FuseCandidate => {
            if containment
                .map(|cfg| cfg.fuse_enabled && !cfg.dry_run)
                .unwrap_or(false)
            {
                "fuse-active"
            } else {
                "dry-run fuse candidate"
            }
        }
    };

    match event.level {
        BehaviorLevel::Observed => tracing::debug!(
            "Behavior activity: level={} score={} pid={} process={} ops=create:{} write:{} rename:{} delete:{} root={} reasons={} mode={}",
            event.level.as_str(),
            event.score,
            event.pid.map(|pid| pid.to_string()).unwrap_or_else(|| "unknown".to_string()),
            process,
            event.file_ops.created,
            event.file_ops.modified,
            event.file_ops.renamed,
            event.file_ops.deleted,
            event.watched_root,
            reasons,
            enforcement_mode
        ),
        BehaviorLevel::Suspicious | BehaviorLevel::ThrottleCandidate => tracing::warn!(
            "Behavior activity: level={} score={} pid={} process={} ops=create:{} write:{} rename:{} delete:{} root={} reasons={} mode={}",
            event.level.as_str(),
            event.score,
            event.pid.map(|pid| pid.to_string()).unwrap_or_else(|| "unknown".to_string()),
            process,
            event.file_ops.created,
            event.file_ops.modified,
            event.file_ops.renamed,
            event.file_ops.deleted,
            event.watched_root,
            reasons,
            enforcement_mode
        ),
        BehaviorLevel::FuseCandidate => tracing::error!(
            "Behavior activity: level={} score={} pid={} process={} ops=create:{} write:{} rename:{} delete:{} root={} reasons={} mode={}",
            event.level.as_str(),
            event.score,
            event.pid.map(|pid| pid.to_string()).unwrap_or_else(|| "unknown".to_string()),
            process,
            event.file_ops.created,
            event.file_ops.modified,
            event.file_ops.renamed,
            event.file_ops.deleted,
            event.watched_root,
            reasons,
            enforcement_mode
        ),
    }
}

fn log_containment_decision(decision: &ContainmentDecision) {
    if let Some(transition) = decision.transition.as_ref() {
        tracing::warn!(
            "Containment transition: {} -> {} pid={} score={} root={} reason={}",
            transition.from.as_str(),
            transition.to.as_str(),
            transition
                .pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            transition.score,
            transition.watched_root,
            transition.reason
        );
    }

    for outcome in &decision.outcomes {
        if outcome.applied {
            tracing::warn!(
                action = ?outcome.action,
                enforcer = outcome.enforcer.as_str(),
                applied = outcome.applied,
                dry_run = outcome.dry_run,
                detail = outcome.detail.as_str(),
                "Containment enforcement outcome"
            );
        } else {
            tracing::info!(
                action = ?outcome.action,
                enforcer = outcome.enforcer.as_str(),
                applied = outcome.applied,
                dry_run = outcome.dry_run,
                detail = outcome.detail.as_str(),
                "Containment enforcement outcome"
            );
        }
    }
}

async fn cleanup_firewall_command() -> Result<()> {
    let backend = detect_backend();
    tracing::info!("Detected firewall backend for cleanup: {:?}", backend);
    cleanup_firewall(&backend).await
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

/// Set up local configuration and attempt server registration immediately.
async fn init() -> Result<()> {
    println!("\n=== BannKenn Agent — Local Setup ===\n");

    let stdin = io::stdin();
    let mut reader = stdin.lock();

    // Server URL
    print!("BannKenn API server URL [http://localhost:3022]: ");
    io::stdout().flush()?;
    let mut server_url = String::new();
    reader.read_line(&mut server_url)?;
    let server_url = server_url.trim();
    let server_url = if server_url.is_empty() {
        "http://localhost:3022".to_string()
    } else {
        server_url.to_string()
    };

    let ca_cert_path = if server_url.starts_with("https://") {
        print!("Custom CA/cert PEM path [blank = system trust]: ");
        io::stdout().flush()?;
        let mut input = String::new();
        reader.read_line(&mut input)?;
        let input = input.trim();
        if input.is_empty() {
            None
        } else {
            Some(input.to_string())
        }
    } else {
        None
    };

    // Agent name (for display on dashboard)
    let hostname = get_hostname();
    print!("Agent name [{}]: ", hostname);
    io::stdout().flush()?;
    let mut agent_name = String::new();
    reader.read_line(&mut agent_name)?;
    let agent_name = agent_name.trim();
    let agent_name = if agent_name.is_empty() {
        hostname
    } else {
        agent_name.to_string()
    };

    // Log source discovery (no manual path entry)
    let log_candidates = discover_log_candidates();
    let log_path =
        select_primary_log_path(&log_candidates).unwrap_or_else(|| "/var/log/auth.log".to_string());

    println!("\nDetected log sources:");
    if log_candidates.is_empty() {
        println!("1. /var/log/auth.log (fallback; file not currently detectable)");
    } else {
        for (idx, path) in log_candidates.iter().enumerate() {
            println!("{}. {}", idx + 1, path);
        }
    }
    println!("Auto-selected log file: {}", log_path);

    // Threshold
    print!("Failed login threshold [5]: ");
    io::stdout().flush()?;
    let mut threshold = String::new();
    reader.read_line(&mut threshold)?;
    let threshold = threshold.trim().parse::<u32>().unwrap_or(5);

    // Window size
    print!("Time window in seconds [60]: ");
    io::stdout().flush()?;
    let mut window_secs = String::new();
    reader.read_line(&mut window_secs)?;
    let window_secs = window_secs.trim().parse::<u64>().unwrap_or(60);

    // Generate a stable UUID for this agent
    let uuid = Uuid::new_v4().to_string();

    let mut config = AgentConfig {
        server_url,
        jwt_token: String::new(), // populated by `connect`
        ca_cert_path,
        agent_name,
        uuid,
        log_paths: log_candidates.clone(),
        log_path,
        threshold,
        window_secs,
        butterfly_shield: None,
        burst: None,
        risk_level: None,
        event_risk: None,
        campaign: Some(default_runtime_campaign_config()),
        mmdb_dir: None,
        containment: Some(default_runtime_containment_config()),
    };

    config.save()?;

    match install_systemd_unit(&std::env::current_exe()?) {
        Ok(true) => {
            println!("Installed systemd unit at {}.", SERVICE_UNIT_PATH);
            println!("Use 'sudo systemctl enable --now bannkenn-agent' after registration.");
        }
        Ok(false) => {
            println!("Systemd not detected; skipping service unit installation.");
        }
        Err(e) if is_permission_denied(&e) => {
            eprintln!(
                "Warning: could not install {} (permission denied). Re-run 'sudo bannkenn-agent init' to install the service automatically.",
                SERVICE_UNIT_PATH
            );
        }
        Err(e) => {
            eprintln!(
                "Warning: failed to install {} automatically: {}",
                SERVICE_UNIT_PATH, e
            );
        }
    }

    println!("\nConfiguration saved.");
    // Release the setup prompt reader before TOFU/connect prompts reuse stdin.
    drop(reader);

    match register_and_persist_agent(&mut config).await {
        Ok(name) => {
            println!("Agent '{}' is ready.", name);
            println!("Run 'sudo systemctl enable --now bannkenn-agent' to start monitoring.");
            println!("The running service keeps the dashboard connection alive; stopping or disabling it stops heartbeats and uploads.\n");
        }
        Err(err) => {
            eprintln!("Registration skipped/failed during init: {}", err);
            println!("Run 'sudo bannkenn-agent connect' to retry registration.");
            println!(
                "Then run 'sudo systemctl enable --now bannkenn-agent' to start monitoring.\n"
            );
        }
    }

    Ok(())
}

async fn uninstall() -> Result<()> {
    let backend = detect_backend();

    uninstall_systemd_unit()?;

    if let Err(e) = cleanup_firewall(&backend).await {
        tracing::warn!("Failed to clean up firewall state during uninstall: {}", e);
    }

    let config_dir = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?
        .join(".config/bannkenn");
    match fs::remove_dir_all(&config_dir) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    let binary_path = std::env::current_exe()?;
    match fs::remove_file(&binary_path) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    println!(
        "Removed systemd service, local config, firewall state, and binary at {}.",
        binary_path.display()
    );
    Ok(())
}

/// Register this agent with the BannKenn server API and save the JWT token.
async fn connect() -> Result<()> {
    let mut config = AgentConfig::load()?;

    let name = register_and_persist_agent(&mut config).await?;
    match install_systemd_unit(&std::env::current_exe()?) {
        Ok(true) => {
            println!(
                "Refreshed systemd unit at {} so the service uses the current agent binary/config path.",
                SERVICE_UNIT_PATH
            );
        }
        Ok(false) => {}
        Err(e) if is_permission_denied(&e) => {
            eprintln!(
                "Warning: could not refresh {} (permission denied). Re-run 'sudo bannkenn-agent connect' or 'sudo bannkenn-agent init' to update the service unit.",
                SERVICE_UNIT_PATH
            );
        }
        Err(e) => {
            eprintln!(
                "Warning: failed to refresh {} automatically: {}",
                SERVICE_UNIT_PATH, e
            );
        }
    }
    println!(
        "Saved dashboard token for '{}'. Start or restart the service to use it.\n",
        name
    );
    Ok(())
}

#[derive(Debug)]
struct HttpProbeResult {
    status: StatusCode,
    server_header: Option<String>,
    cf_ray: Option<String>,
    content_type: Option<String>,
    body_preview: Option<String>,
}

async fn connect_test() -> Result<()> {
    let config = AgentConfig::load()?;

    if config.server_url.trim().is_empty() {
        return Err(anyhow::anyhow!(
            "No server URL configured. Run 'bannkenn-agent init' or 'bannkenn-agent connect' first."
        ));
    }

    let parsed_url = Url::parse(&config.server_url)
        .map_err(|err| anyhow::anyhow!("invalid server_url: {}", err))?;
    let host = parsed_url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("server_url is missing a hostname"))?;
    let port = parsed_url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("server_url is missing a port and has no known default"))?;
    let agent_name = if config.agent_name.trim().is_empty() {
        get_hostname()
    } else {
        config.agent_name.clone()
    };

    println!("BannKenn connectivity diagnostic");
    println!("Server URL: {}", config.server_url);
    println!("Agent name: {}", agent_name);
    println!(
        "JWT token: {}",
        if config.jwt_token.trim().is_empty() {
            "missing"
        } else {
            "configured"
        }
    );
    println!(
        "CA trust: {}",
        config
            .ca_cert_path
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("system trust store")
    );
    println!();

    let resolved_addrs = match resolve_target_addresses(host, port).await {
        Ok(addrs) => {
            println!(
                "1. DNS lookup: OK -> {}",
                addrs
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            addrs
        }
        Err(err) => {
            eprintln!("1. DNS lookup: FAILED -> {}", err);
            return Err(anyhow::anyhow!("connectivity diagnostic failed"));
        }
    };

    match connect_to_resolved_target(&resolved_addrs).await {
        Ok((addr, latency_ms)) => {
            println!("2. TCP connect: OK -> {} ({} ms)", addr, latency_ms);
        }
        Err(err) => {
            eprintln!("2. TCP connect: FAILED -> {}", err);
            return Err(anyhow::anyhow!("connectivity diagnostic failed"));
        }
    }

    let http = build_diagnostic_http_client(config.ca_cert_path.as_deref())?;
    let base = config.server_url.trim_end_matches('/');
    let health_url = format!("{}/api/v1/health", base);
    let heartbeat_url = format!("{}/api/v1/agents/heartbeat", base);

    println!("3. Health probe: GET {}", health_url);
    match send_http_probe(&http, Method::GET, &health_url, None, None).await {
        Ok(probe) => {
            print_probe_summary("   Health response", &probe);
            if !probe.status.is_success() {
                print_probe_failure_guidance("health", &probe);
                return Err(anyhow::anyhow!("connectivity diagnostic failed"));
            }
        }
        Err(err) => {
            print_request_failure("health", &config.server_url, &err);
            return Err(anyhow::anyhow!("connectivity diagnostic failed"));
        }
    }

    println!("4. Heartbeat probe: POST {}", heartbeat_url);
    if config.jwt_token.trim().is_empty() {
        eprintln!(
            "   Heartbeat skipped: jwt_token is missing. Run 'bannkenn-agent connect' first."
        );
        return Err(anyhow::anyhow!("connectivity diagnostic failed"));
    }

    let heartbeat_body = json!({
        "butterfly_shield_enabled": config.butterfly_shield.as_ref().map(|cfg| cfg.enabled),
    });

    match send_http_probe(
        &http,
        Method::POST,
        &heartbeat_url,
        Some(&config.jwt_token),
        Some(heartbeat_body),
    )
    .await
    {
        Ok(probe) => {
            print_probe_summary("   Heartbeat response", &probe);
            if !probe.status.is_success() {
                print_probe_failure_guidance("heartbeat", &probe);
                return Err(anyhow::anyhow!("connectivity diagnostic failed"));
            }
        }
        Err(err) => {
            print_request_failure("heartbeat", &config.server_url, &err);
            return Err(anyhow::anyhow!("connectivity diagnostic failed"));
        }
    }

    println!(
        "Diagnostic complete: DNS resolution, TCP reachability, HTTP health, and authenticated heartbeat all succeeded."
    );
    Ok(())
}

async fn resolve_target_addresses(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let resolved = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("DNS lookup timed out after 5 seconds"))?
    .map_err(|err| anyhow::anyhow!("failed to resolve {}:{}: {}", host, port, err))?;

    let addrs = resolved.collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(anyhow::anyhow!(
            "DNS lookup returned no addresses for {}:{}",
            host,
            port
        ));
    }

    Ok(addrs)
}

async fn connect_to_resolved_target(addrs: &[SocketAddr]) -> Result<(SocketAddr, u128)> {
    let mut errors = Vec::new();

    for addr in addrs {
        let start = std::time::Instant::now();
        match tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr))
            .await
        {
            Ok(Ok(stream)) => {
                drop(stream);
                return Ok((*addr, start.elapsed().as_millis()));
            }
            Ok(Err(err)) => errors.push(format!("{} ({})", addr, err)),
            Err(_) => errors.push(format!("{} (timed out after 5 seconds)", addr)),
        }
    }

    Err(anyhow::anyhow!(
        "could not connect to any resolved address: {}",
        errors.join("; ")
    ))
}

fn build_diagnostic_http_client(ca_cert_path: Option<&str>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(format!(
            "bannkenn-agent/{} connecttest",
            env!("CARGO_PKG_VERSION")
        ));

    if let Some(path) = ca_cert_path.filter(|value| !value.trim().is_empty()) {
        let pem = fs::read(path)?;
        let cert = Certificate::from_pem(&pem)?;
        builder = builder.add_root_certificate(cert);
    }

    Ok(builder.build()?)
}

async fn send_http_probe(
    client: &reqwest::Client,
    method: Method,
    url: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
) -> std::result::Result<HttpProbeResult, reqwest::Error> {
    let mut request = client.request(method, url);
    if let Some(token) = token {
        request = request.header("Authorization", format!("Bearer {}", token));
    }
    if let Some(body) = body {
        request = request.json(&body);
    }

    let response = request.send().await?;
    let headers = response.headers().clone();
    let status = response.status();
    let body_preview = preview_response_body(&response.text().await.unwrap_or_default());

    Ok(HttpProbeResult {
        status,
        server_header: header_value(&headers, "server"),
        cf_ray: header_value(&headers, "cf-ray"),
        content_type: header_value(&headers, "content-type"),
        body_preview,
    })
}

fn print_probe_summary(label: &str, probe: &HttpProbeResult) {
    let reason = probe.status.canonical_reason().unwrap_or("Unknown");
    println!("{}: {} {}", label, probe.status.as_u16(), reason);
    if let Some(server) = &probe.server_header {
        println!("     server: {}", server);
    }
    if let Some(cf_ray) = &probe.cf_ray {
        println!("     cf-ray: {}", cf_ray);
    }
    if probe.status.is_success() && is_cloudflare_response(probe) {
        println!("     request reached the Cloudflare proxy successfully");
    }
}

fn print_probe_failure_guidance(stage: &str, probe: &HttpProbeResult) {
    if stage == "heartbeat" && probe.status == StatusCode::UNAUTHORIZED {
        eprintln!(
            "     The BannKenn API rejected the saved JWT token. Re-run 'bannkenn-agent connect' to refresh the agent token."
        );
    } else if stage == "heartbeat" && probe.status == StatusCode::FORBIDDEN {
        if is_cloudflare_response(probe) {
            eprintln!(
                "     Cloudflare returned the heartbeat response, so DNS/TCP/TLS succeeded. Check Cloudflare proxy/WAF rules or origin reachability for /api/v1/agents/heartbeat."
            );
        } else {
            eprintln!(
                "     The request reached the server or reverse proxy, but the heartbeat endpoint was forbidden. Check proxy auth rules and server logs."
            );
        }
    } else if is_cloudflare_response(probe) {
        eprintln!(
            "     Cloudflare answered this request, so DNS/TCP/TLS are working. The failure is likely at the proxy/origin layer rather than basic connectivity."
        );
    } else {
        eprintln!(
            "     The request reached the server or reverse proxy, but the endpoint returned an unexpected status."
        );
    }

    if let Some(content_type) = &probe.content_type {
        eprintln!("     content-type: {}", content_type);
    }
    if let Some(body_preview) = &probe.body_preview {
        eprintln!("     body preview: {}", body_preview);
    }
}

fn print_request_failure(stage: &str, server_url: &str, err: &reqwest::Error) {
    eprintln!("   {} request failed: {}", stage, err);
    if is_unknown_issuer_std_error(err) {
        eprintln!(
            "     TLS certificate is not trusted. Set ca_cert_path in ~/.config/bannkenn/agent.toml or re-run 'bannkenn-agent connect' and accept the certificate fingerprint."
        );
    } else if server_url.starts_with("https://") && is_https_plain_http_mismatch_std_error(err) {
        eprintln!(
            "     HTTPS was requested, but that port appears to be serving plain HTTP instead of TLS. Use 'http://' for a non-TLS server, or enable TLS on the server port."
        );
    } else if err.is_timeout() {
        eprintln!("     The request timed out after the TCP connection succeeded.");
    } else if err.is_connect() {
        eprintln!(
            "     The HTTP client could not establish the application-layer connection even though the TCP probe completed. Check TLS settings, reverse-proxy routing, or intermediate filtering."
        );
    }
}

fn header_value(headers: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn preview_response_body(body: &str) -> Option<String> {
    let collapsed = body.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }

    let mut preview = collapsed.chars().take(200).collect::<String>();
    if collapsed.chars().count() > 200 {
        preview.push_str("...");
    }
    Some(preview)
}

fn is_cloudflare_response(probe: &HttpProbeResult) -> bool {
    probe.cf_ray.is_some()
        || probe
            .server_header
            .as_deref()
            .map(|value| value.to_ascii_lowercase().contains("cloudflare"))
            .unwrap_or(false)
}

/// Return the machine hostname, trying several sources.
fn get_hostname() -> String {
    if let Ok(h) = std::env::var("HOSTNAME") {
        let h = h.trim().to_string();
        if !h.is_empty() {
            return h;
        }
    }
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
        let h = h.trim().to_string();
        if !h.is_empty() {
            return h;
        }
    }
    "bannkenn-agent".to_string()
}

fn error_chain_contains_any(err: &(dyn std::error::Error + 'static), needles: &[&str]) -> bool {
    let mut current = Some(err);
    while let Some(cause) = current {
        let text = cause.to_string();
        if needles.iter().any(|needle| text.contains(needle)) {
            return true;
        }
        current = cause.source();
    }
    false
}

fn is_unknown_issuer_error(err: &anyhow::Error) -> bool {
    is_unknown_issuer_std_error(err.as_ref())
}

fn is_https_plain_http_mismatch_error(err: &anyhow::Error) -> bool {
    is_https_plain_http_mismatch_std_error(err.as_ref())
}

fn is_unknown_issuer_std_error(err: &(dyn std::error::Error + 'static)) -> bool {
    error_chain_contains_any(err, &["UnknownIssuer"])
}

fn is_https_plain_http_mismatch_std_error(err: &(dyn std::error::Error + 'static)) -> bool {
    error_chain_contains_any(
        err,
        &[
            "InvalidContentType",
            "wrong version number",
            "packet length too long",
        ],
    )
}

fn prompt_yes_no(prompt: &str) -> Result<bool> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    let answer = answer.trim();
    Ok(matches!(answer, "y" | "Y" | "yes" | "YES" | "Yes"))
}

async fn trust_on_first_use(config: &mut AgentConfig) -> Result<bool> {
    let cert = fetch_presented_certificate(&config.server_url).await?;
    println!(
        "Server presented an untrusted certificate for {}",
        config.server_url
    );
    println!("SHA-256 fingerprint: {}", cert.sha256_fingerprint);

    if !prompt_yes_no("Trust and pin this certificate for future connections? [y/N]: ")? {
        return Ok(false);
    }

    let path = save_presented_certificate(&config.server_url, &cert)?;
    config.ca_cert_path = Some(path.display().to_string());
    config.save()?;

    println!("Pinned server certificate at {}.", path.display());
    Ok(true)
}

fn is_permission_denied(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .map(|io_err| io_err.kind() == io::ErrorKind::PermissionDenied)
            .unwrap_or(false)
    })
}

fn discover_log_candidates() -> Vec<String> {
    let mut found = BTreeSet::new();

    // Common host auth/system logs.
    for path in [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog",
        "/var/log/messages",
    ] {
        add_readable_file(path, &mut found);
    }

    // Docker container JSON logs: /var/lib/docker/containers/<id>/<id>-json.log
    collect_docker_container_logs("/var/lib/docker/containers", &mut found);

    // Kubernetes-style logs if present.
    collect_logs_from_tree("/var/log/containers", 1, 500, &mut found);
    collect_logs_from_tree("/var/log/pods", 5, 2000, &mut found);

    // VM or external mounts (if mounted and readable from this host).
    for mount_root in ["/mnt", "/media", "/run/media", "/vmfs/volumes"] {
        collect_named_logs_from_tree(
            mount_root,
            &["auth.log", "secure", "syslog", "messages"],
            6,
            2000,
            &mut found,
        );
    }

    found.into_iter().collect()
}

fn select_primary_log_path(candidates: &[String]) -> Option<String> {
    if candidates.is_empty() {
        return None;
    }

    let priorities = [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/containers/",
        "/var/lib/docker/containers/",
        "/var/log/pods/",
        "/mnt/",
        "/media/",
        "/run/media/",
        "/vmfs/volumes/",
    ];

    candidates
        .iter()
        .min_by_key(|path| {
            priorities
                .iter()
                .position(|prefix| path == prefix || path.starts_with(prefix))
                .unwrap_or(priorities.len())
        })
        .cloned()
}

fn add_readable_file(path: &str, out: &mut BTreeSet<String>) {
    let p = Path::new(path);
    if p.is_file() && fs::File::open(p).is_ok() {
        out.insert(path.to_string());
    }
}

fn collect_docker_container_logs(root: &str, out: &mut BTreeSet<String>) {
    let root_path = Path::new(root);
    if !root_path.is_dir() {
        return;
    }

    let Ok(container_dirs) = fs::read_dir(root_path) else {
        return;
    };

    for dir in container_dirs.flatten() {
        let path = dir.path();
        if !path.is_dir() {
            continue;
        }
        let Ok(files) = fs::read_dir(&path) else {
            continue;
        };
        for file in files.flatten() {
            let file_path = file.path();
            if !file_path.is_file() {
                continue;
            }
            let Some(name) = file_path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if name.ends_with("-json.log") && fs::File::open(&file_path).is_ok() {
                out.insert(file_path.to_string_lossy().to_string());
            }
        }
    }
}

fn collect_logs_from_tree(
    root: &str,
    max_depth: usize,
    max_files: usize,
    out: &mut BTreeSet<String>,
) {
    let root_path = Path::new(root);
    if !root_path.is_dir() {
        return;
    }

    let mut stack: Vec<(std::path::PathBuf, usize)> = vec![(root_path.to_path_buf(), 0)];
    let mut seen_files = 0usize;

    while let Some((dir, depth)) = stack.pop() {
        if seen_files >= max_files {
            break;
        }

        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries.flatten() {
            if seen_files >= max_files {
                break;
            }

            let path = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if (name.ends_with(".log") || name.ends_with("-json.log"))
                        && fs::File::open(&path).is_ok()
                    {
                        out.insert(path.to_string_lossy().to_string());
                        seen_files += 1;
                    }
                }
            } else if path.is_dir() && depth < max_depth {
                stack.push((path, depth + 1));
            }
        }
    }
}

fn collect_named_logs_from_tree(
    root: &str,
    names: &[&str],
    max_depth: usize,
    max_files: usize,
    out: &mut BTreeSet<String>,
) {
    let root_path = Path::new(root);
    if !root_path.is_dir() {
        return;
    }

    let mut stack: Vec<(std::path::PathBuf, usize)> = vec![(root_path.to_path_buf(), 0)];
    let mut seen_files = 0usize;

    while let Some((dir, depth)) = stack.pop() {
        if seen_files >= max_files {
            break;
        }

        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries.flatten() {
            if seen_files >= max_files {
                break;
            }

            let path = entry.path();
            if path.is_file() {
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if names.contains(&name) && fs::File::open(&path).is_ok() {
                    out.insert(path.to_string_lossy().to_string());
                    seen_files += 1;
                }
            } else if path.is_dir() && depth < max_depth {
                stack.push((path, depth + 1));
            }
        }
    }
}

async fn register_agent_and_get_token(
    server_url: &str,
    agent_name: &str,
    agent_uuid: &str,
    ca_cert_path: Option<&str>,
) -> Result<String> {
    let base = server_url.trim_end_matches('/');
    let url = format!("{}/api/v1/agents/register", base);

    let response = build_http_client(ca_cert_path)?
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&json!({ "name": agent_name, "uuid": agent_uuid }))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(anyhow::anyhow!(
            "agent registration failed with {}: {}",
            status,
            text
        ));
    }

    let payload: RegisterAgentResponse = response.json().await?;
    if payload.token.is_empty() {
        return Err(anyhow::anyhow!("server returned empty token"));
    }

    Ok(payload.token)
}

async fn register_and_persist_agent(config: &mut AgentConfig) -> Result<String> {
    if config.server_url.is_empty() {
        return Err(anyhow::anyhow!(
            "No server URL configured. Run 'bannkenn-agent init' first."
        ));
    }

    if config.uuid.is_empty() {
        config.uuid = Uuid::new_v4().to_string();
    }

    let name = if config.agent_name.is_empty() {
        get_hostname()
    } else {
        config.agent_name.clone()
    };

    println!("\nConnecting to {} as '{}'…", config.server_url, name);

    let token = match register_agent_and_get_token(
        &config.server_url,
        &name,
        &config.uuid,
        config.ca_cert_path.as_deref(),
    )
    .await
    {
        Ok(token) => token,
        Err(err)
            if is_unknown_issuer_error(&err)
                && config.server_url.starts_with("https://")
                && config.ca_cert_path.is_none() =>
        {
            if trust_on_first_use(config).await? {
                register_agent_and_get_token(
                    &config.server_url,
                    &name,
                    &config.uuid,
                    config.ca_cert_path.as_deref(),
                )
                .await?
            } else {
                return Err(anyhow::anyhow!(
                    "TLS certificate was not trusted. Re-run connect and accept the fingerprint, or set ca_cert_path manually."
                ));
            }
        }
        Err(err) if is_unknown_issuer_error(&err) => {
            return Err(anyhow::anyhow!(
                "TLS certificate is not trusted. Copy the server certificate/CA PEM to this machine and set ca_cert_path in ~/.config/bannkenn/agent.toml, or install that certificate/CA into the system trust store. Original error: {}",
                err
            ));
        }
        Err(err)
            if config.server_url.starts_with("https://")
                && is_https_plain_http_mismatch_error(&err) =>
        {
            return Err(anyhow::anyhow!(
                "HTTPS was requested for {}, but that port appears to be serving plain HTTP instead of TLS. Use an `http://` server_url for a non-TLS BannKenn server, or enable TLS on the server port before using `https://`. Original error: {}",
                config.server_url,
                err
            ));
        }
        Err(err) => return Err(err),
    };
    config.jwt_token = token;
    config.agent_name = name.clone();
    config.save()?;

    println!("Agent '{}' registered successfully.", name);
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::{
        is_cloudflare_response, is_https_plain_http_mismatch_error, Cli, Commands, HttpProbeResult,
    };
    use clap::Parser;
    use reqwest::StatusCode;

    #[test]
    fn plain_http_on_https_error_is_detected() {
        let err = anyhow::anyhow!(
            "error trying to connect: received corrupt message of type InvalidContentType"
        );
        assert!(is_https_plain_http_mismatch_error(&err));
    }

    #[test]
    fn unrelated_tls_error_is_not_classified_as_plain_http_mismatch() {
        let err = anyhow::anyhow!("certificate verify failed: UnknownIssuer");
        assert!(!is_https_plain_http_mismatch_error(&err));
    }

    #[test]
    fn connecttest_command_parses() {
        let cli = Cli::parse_from(["bannkenn-agent", "connecttest"]);
        assert!(matches!(cli.command, Some(Commands::ConnectTest)));
    }

    #[test]
    fn cloudflare_probe_is_detected() {
        let probe = HttpProbeResult {
            status: StatusCode::FORBIDDEN,
            server_header: Some("cloudflare".to_string()),
            cf_ray: Some("88e4ec9ec8c8e123-NRT".to_string()),
            content_type: Some("text/html".to_string()),
            body_preview: Some("Access denied".to_string()),
        };

        assert!(is_cloudflare_response(&probe));
    }
}
