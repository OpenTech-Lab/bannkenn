mod burst;
mod butterfly;
mod campaign;
mod client;
mod config;
mod event_risk;
mod firewall;
mod geoip;
mod outbox;
mod patterns;
mod risk_level;
mod service;
mod shared_risk;
mod sync;
mod updater;
mod watcher;

use anyhow::Result;
use clap::{Parser, Subcommand};
use reqwest::Client as HttpClient;
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, Notify, RwLock};
use tokio::time::{interval, Duration};
use uuid::Uuid;

use crate::client::ApiClient;
use crate::config::{default_runtime_campaign_config, AgentConfig, OfflineAgentState};
use crate::firewall::{block_ip, cleanup_firewall, detect_backend, init_firewall};
use crate::outbox::{flush_pending, Outbox, OutboxPayload};
use crate::service::{install_systemd_unit, uninstall_systemd_unit, SERVICE_UNIT_PATH};
use crate::shared_risk::SharedRiskSnapshot;
use crate::watcher::{watch, BlockOutcome, SecurityEvent};

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
    /// Initialize local configuration (does not connect to the dashboard server)
    Init,
    /// Stop, disable, and remove the systemd service plus local agent state
    Uninstall,
    /// Register this agent with the dashboard server (run after `init`)
    Connect,
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Init) => init().await?,
        Some(Commands::Uninstall) => uninstall().await?,
        Some(Commands::Connect) => connect().await?,
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
            "Configuration incomplete. Run 'bannkenn-agent init' then 'bannkenn-agent connect'"
        );
        return Err(anyhow::anyhow!(
            "Configuration incomplete. Run 'bannkenn-agent init' then 'bannkenn-agent connect'"
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

    let api_client = ApiClient::new(config.server_url.clone(), config.jwt_token.clone());
    let offline_state_path = OfflineAgentState::state_path()?;
    let offline_state = OfflineAgentState::load(&offline_state_path);

    // Shared set of IPs already present in the server's block list DB.
    // Pre-populated at startup; kept in sync by sync_loop.
    // Maps IP → source name (e.g. "ipsum_feed", "agent") so that watcher can
    // report which database listed the IP when emitting level=listed events.
    let known_blocked_ips: Arc<RwLock<HashMap<String, String>>> =
        Arc::new(RwLock::new(offline_state.known_blocked_ips.clone()));
    let enforced_blocked_ips: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));
    let shared_risk_snapshot: Arc<RwLock<SharedRiskSnapshot>> =
        Arc::new(RwLock::new(offline_state.shared_risk_snapshot.clone()));

    if !offline_state.known_blocked_ips.is_empty() {
        let mut restored = 0u32;
        let mut failed = 0u32;
        for ip in offline_state.known_blocked_ips.keys() {
            match block_ip(ip, &backend).await {
                Ok(_) => {
                    restored += 1;
                    enforced_blocked_ips.write().await.insert(ip.clone());
                }
                Err(e) => {
                    tracing::warn!("cache: failed to restore firewall block for {}: {}", ip, e);
                    failed += 1;
                }
            }
        }
        tracing::info!(
            "Loaded cached offline state: {} blocked IP(s), shared-risk categories={}, restored {} firewall rule(s) ({} failed)",
            offline_state.known_blocked_ips.len(),
            offline_state.shared_risk_snapshot.categories.len(),
            restored,
            failed
        );
    }

    // Initial fetch: load all existing block-list IPs before starting the watcher
    // so detections are classified "listed" from the very first event.
    // Also re-applies firewall rules so blocks survive agent/host restarts.
    let init_client = ApiClient::new(config.server_url.clone(), config.jwt_token.clone());
    match init_client.fetch_decisions_since(0).await {
        Ok(decisions) => {
            let mut restored = 0u32;
            let mut failed = 0u32;
            {
                let mut set = known_blocked_ips.write().await;
                for d in &decisions {
                    set.insert(d.ip.clone(), d.source.clone());
                }
            }
            for d in &decisions {
                match block_ip(&d.ip, &backend).await {
                    Ok(_) => {
                        restored += 1;
                        enforced_blocked_ips.write().await.insert(d.ip.clone());
                    }
                    Err(e) => {
                        tracing::warn!(
                            "startup: failed to restore firewall block for {}: {}",
                            d.ip,
                            e
                        );
                        failed += 1;
                    }
                }
            }
            tracing::info!(
                "Loaded {} known blocked IP(s) from server; restored {} firewall rule(s) ({} failed)",
                decisions.len(),
                restored,
                failed
            );
            sync::persist_offline_state(&known_blocked_ips, &shared_risk_snapshot).await;
        }
        Err(e) => tracing::warn!("Failed to load initial block list: {}", e),
    }

    match init_client.fetch_shared_risk_profile().await {
        Ok(profile) => {
            *shared_risk_snapshot.write().await = profile;
            sync::persist_offline_state(&known_blocked_ips, &shared_risk_snapshot).await;
        }
        Err(e) => tracing::warn!("Failed to load initial shared-risk profile: {}", e),
    }

    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(1000);
    let (block_outcome_tx, block_outcome_rx) = mpsc::channel::<BlockOutcome>(1000);
    let outbox = Arc::new(Mutex::new(Outbox::load_default()?));
    let outbox_notify = Arc::new(Notify::new());

    let config_arc = Arc::new(config);

    let config_for_watcher = Arc::clone(&config_arc);
    let known_ips_for_watcher = Arc::clone(&known_blocked_ips);
    let enforced_ips_for_watcher = Arc::clone(&enforced_blocked_ips);
    let shared_risk_for_watcher = Arc::clone(&shared_risk_snapshot);
    let watcher_handle = tokio::spawn(async move {
        if let Err(e) = watch(
            config_for_watcher,
            tx,
            known_ips_for_watcher,
            enforced_ips_for_watcher,
            shared_risk_for_watcher,
            block_outcome_rx,
        )
        .await
        {
            tracing::error!("Watcher error: {}", e);
        }
    });

    let sync_client = ApiClient::new(config_arc.server_url.clone(), config_arc.jwt_token.clone());
    let sync_handle = tokio::spawn(sync::sync_loop(
        sync_client,
        Arc::clone(&known_blocked_ips),
        Arc::clone(&enforced_blocked_ips),
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

    let heartbeat_client =
        ApiClient::new(config_arc.server_url.clone(), config_arc.jwt_token.clone());
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
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        let event = tokio::select! {
            maybe_event = rx.recv() => match maybe_event {
                Some(event) => event,
                None => break,
            },
            reason = &mut shutdown => {
                shutdown_reason = Some(reason);
                break;
            }
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
                    },
                    &outbox_notify,
                )
                .await;
            }
            "block" => {
                // Apply firewall IMMEDIATELY — before any network I/O.
                match block_ip(&event.ip, &backend).await {
                    Ok(_) => {
                        tracing::info!("Blocked IP: {}", event.ip);
                        enforced_blocked_ips.write().await.insert(event.ip.clone());
                        let _ = block_outcome_tx
                            .send(BlockOutcome::Enforced(event.ip.clone()))
                            .await;
                    }
                    Err(e) => {
                        tracing::error!("Failed to block IP {}: {}", event.ip, e);
                        let _ = block_outcome_tx
                            .send(BlockOutcome::Failed(event.ip.clone()))
                            .await;
                    }
                }
                // Update shared set so watcher won't re-process this IP.
                known_blocked_ips
                    .write()
                    .await
                    .insert(event.ip.clone(), "agent".to_string());
                sync::persist_offline_state(&known_blocked_ips, &shared_risk_snapshot).await;
                enqueue_outbox(
                    &outbox,
                    OutboxPayload::Decision {
                        ip: event.ip.clone(),
                        reason: event.reason.clone(),
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
                    },
                    &outbox_notify,
                )
                .await;
            }
            "listed" => {
                // IP already in block list DB: apply firewall IMMEDIATELY.
                match block_ip(&event.ip, &backend).await {
                    Ok(_) => {
                        tracing::info!("Listed IP blocked by firewall: {}", event.ip);
                        enforced_blocked_ips.write().await.insert(event.ip.clone());
                        let _ = block_outcome_tx
                            .send(BlockOutcome::Enforced(event.ip.clone()))
                            .await;
                    }
                    Err(e) => {
                        tracing::error!("Failed to block listed IP {}: {}", event.ip, e);
                        let _ = block_outcome_tx
                            .send(BlockOutcome::Failed(event.ip.clone()))
                            .await;
                    }
                }
                enqueue_outbox(
                    &outbox,
                    OutboxPayload::Telemetry {
                        ip: event.ip.clone(),
                        reason: event.reason.clone(),
                        level: event.level.clone(),
                        log_path: Some(event.log_path.clone()),
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
                    },
                    &outbox_notify,
                )
                .await;
            }
        }
    }

    watcher_handle.abort();
    sync_handle.abort();
    flush_handle.abort();
    heartbeat_handle.abort();

    let _ = watcher_handle.await;
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

/// Set up local configuration. Does NOT connect to the server.
async fn init() -> Result<()> {
    println!("\n=== BannKenn Agent — Local Setup ===\n");

    let stdin = io::stdin();
    let mut reader = stdin.lock();

    // Server URL
    print!("Dashboard server URL [http://localhost:3022]: ");
    io::stdout().flush()?;
    let mut server_url = String::new();
    reader.read_line(&mut server_url)?;
    let server_url = server_url.trim();
    let server_url = if server_url.is_empty() {
        "http://localhost:3022".to_string()
    } else {
        server_url.to_string()
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

    let config = AgentConfig {
        server_url,
        jwt_token: String::new(), // populated by `connect`
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
    };

    config.save()?;

    match install_systemd_unit(&std::env::current_exe()?) {
        Ok(true) => {
            println!("Installed systemd unit at {}.", SERVICE_UNIT_PATH);
            println!("Use 'sudo systemctl enable --now bannkenn-agent' after connect.");
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
    println!("Run 'bannkenn-agent connect' to register with the dashboard server.");
    println!("Then run 'sudo systemctl enable --now bannkenn-agent' to start monitoring.\n");

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

/// Register this agent with the dashboard server and save the JWT token.
async fn connect() -> Result<()> {
    let mut config = AgentConfig::load()?;

    if config.server_url.is_empty() {
        return Err(anyhow::anyhow!(
            "No server URL configured. Run 'bannkenn-agent init' first."
        ));
    }

    // Ensure there is a UUID (generate if missing, e.g. old config)
    if config.uuid.is_empty() {
        config.uuid = Uuid::new_v4().to_string();
    }

    // Use stored agent_name or fall back to hostname
    let name = if config.agent_name.is_empty() {
        get_hostname()
    } else {
        config.agent_name.clone()
    };

    println!("\nConnecting to {} as '{}'…", config.server_url, name);

    match register_agent_and_get_token(&config.server_url, &name, &config.uuid).await {
        Ok(token) => {
            config.jwt_token = token;
            config.agent_name = name.clone();
            config.save()?;
            println!("Agent '{}' registered successfully.", name);
            println!("Starting agent…\n");
        }
        Err(e) => {
            eprintln!("Connection failed: {}", e);
            return Err(e);
        }
    }

    run().await
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
) -> Result<String> {
    let base = server_url.trim_end_matches('/');
    let url = format!("{}/api/v1/agents/register", base);

    let response = HttpClient::new()
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
