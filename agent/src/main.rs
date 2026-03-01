mod butterfly;
mod client;
mod config;
mod firewall;
mod patterns;
mod sync;
mod watcher;

use anyhow::Result;
use clap::{Parser, Subcommand};
use reqwest::Client as HttpClient;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeSet;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use uuid::Uuid;

use crate::client::ApiClient;
use crate::config::AgentConfig;
use crate::firewall::{block_ip, detect_backend};
use crate::watcher::{watch, SecurityEvent};

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
    /// Initialize local configuration (does not connect to the dashboard server)
    Init,
    /// Register this agent with the dashboard server (run after `init`)
    Connect,
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
        Some(Commands::Connect) => connect().await?,
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

    let backend = detect_backend();
    tracing::info!("Detected firewall backend: {:?}", backend);

    let api_client = ApiClient::new(config.server_url.clone(), config.jwt_token.clone());

    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(1000);

    let config_arc = Arc::new(config);

    let config_for_watcher = Arc::clone(&config_arc);
    let watcher_handle = tokio::spawn(async move {
        if let Err(e) = watch(config_for_watcher, tx).await {
            tracing::error!("Watcher error: {}", e);
        }
    });

    let sync_client = ApiClient::new(config_arc.server_url.clone(), config_arc.jwt_token.clone());
    tokio::spawn(sync::sync_loop(sync_client));

    let heartbeat_client =
        ApiClient::new(config_arc.server_url.clone(), config_arc.jwt_token.clone());
    let butterfly_enabled = config_arc.butterfly_shield.as_ref().map(|c| c.enabled);
    tokio::spawn(async move {
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

    while let Some(event) = rx.recv().await {
        tracing::info!(
            "Security event received: IP={}, level={}, attempts={}/{}, at={}",
            event.ip,
            event.level,
            event.attempts,
            event.effective_threshold,
            event.timestamp
        );

        match api_client
            .report_telemetry(&event.ip, &event.reason, &event.level, Some(&event.log_path))
            .await
        {
            Ok(_) => tracing::debug!("Telemetry sent: {} {}", event.level, event.ip),
            Err(e) => tracing::warn!("Failed to report telemetry for IP {}: {}", event.ip, e),
        }

        if event.level == "block" {
            match block_ip(&event.ip, &backend).await {
                Ok(_) => tracing::info!("Successfully blocked IP: {}", event.ip),
                Err(e) => tracing::error!("Failed to block IP {}: {}", event.ip, e),
            }

            match api_client.report_decision(&event.ip, &event.reason).await {
                Ok(_) => tracing::info!("Successfully reported decision for IP: {}", event.ip),
                Err(e) => tracing::warn!("Failed to report decision for IP {}: {}", event.ip, e),
            }
        }
    }

    let _ = watcher_handle.await;

    Ok(())
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
    };

    config.save()?;

    println!("\nConfiguration saved.");
    println!("Run 'bannkenn-agent connect' to register with the dashboard server.");
    println!("Then run 'bannkenn-agent run' to start monitoring.\n");

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
