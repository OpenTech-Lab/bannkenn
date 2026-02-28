mod client;
mod config;
mod firewall;
mod watcher;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::io::{self, BufRead, Write};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing_subscriber;

use crate::client::ApiClient;
use crate::config::AgentConfig;
use crate::firewall::{block_ip, detect_backend};
use crate::watcher::{watch, BlockEvent};

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
    /// Initialize configuration
    Init,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Init) => init().await?,
        Some(Commands::Run) | None => run().await?,
    }

    Ok(())
}

/// Run the agent
async fn run() -> Result<()> {
    tracing::info!("Starting BannKenn Agent");

    // Load configuration
    let config = AgentConfig::load()?;

    // Validate configuration
    if config.server_url.is_empty() || config.jwt_token.is_empty() {
        tracing::error!("Configuration incomplete. Please run 'bannkenn-agent init'");
        return Err(anyhow::anyhow!(
            "Configuration incomplete. Run 'bannkenn-agent init'"
        ));
    }

    tracing::info!(
        "Configured to connect to: {}",
        config.server_url
    );
    tracing::info!("Monitoring log file: {}", config.log_path);
    tracing::info!(
        "Threshold: {} attempts in {} seconds",
        config.threshold, config.window_secs
    );

    // Detect firewall backend
    let backend = detect_backend();
    tracing::info!("Detected firewall backend: {:?}", backend);

    // Create API client
    let api_client = ApiClient::new(config.server_url.clone(), config.jwt_token.clone());

    // Create channel for block events
    let (tx, mut rx) = mpsc::channel::<BlockEvent>(100);

    let config_arc = Arc::new(config);

    // Spawn watcher task
    let config_for_watcher = Arc::clone(&config_arc);
    let watcher_handle = tokio::spawn(async move {
        if let Err(e) = watch(config_for_watcher, tx).await {
            tracing::error!("Watcher error: {}", e);
        }
    });

    // Main event loop: receive block events and process them
    while let Some(event) = rx.recv().await {
        tracing::info!(
            "Block event received: IP={}, reason={}",
            event.ip,
            event.reason
        );

        // Block the IP in firewall
        match block_ip(&event.ip, &backend).await {
            Ok(_) => {
                tracing::info!("Successfully blocked IP: {}", event.ip);
            }
            Err(e) => {
                tracing::error!("Failed to block IP {}: {}", event.ip, e);
            }
        }

        // Report decision to server
        match api_client.report_decision(&event.ip, &event.reason).await {
            Ok(_) => {
                tracing::info!("Successfully reported decision for IP: {}", event.ip);
            }
            Err(e) => {
                tracing::warn!("Failed to report decision for IP {}: {}", event.ip, e);
            }
        }
    }

    // Wait for watcher to finish (should run indefinitely)
    let _ = watcher_handle.await;

    Ok(())
}

/// Interactive configuration setup
async fn init() -> Result<()> {
    println!("\n=== BannKenn Agent Configuration ===\n");

    let stdin = io::stdin();
    let mut reader = stdin.lock();

    // Server URL
    print!("Server URL [http://localhost:8080]: ");
    io::stdout().flush()?;
    let mut server_url = String::new();
    reader.read_line(&mut server_url)?;
    let server_url = server_url.trim();
    let server_url = if server_url.is_empty() {
        "http://localhost:8080".to_string()
    } else {
        server_url.to_string()
    };

    // JWT Token
    print!("JWT Token []: ");
    io::stdout().flush()?;
    let mut jwt_token = String::new();
    reader.read_line(&mut jwt_token)?;
    let jwt_token = jwt_token.trim().to_string();

    if jwt_token.is_empty() {
        eprintln!("Error: JWT token is required");
        return Err(anyhow::anyhow!("JWT token is required"));
    }

    // Log path
    print!("Log file path [/var/log/auth.log]: ");
    io::stdout().flush()?;
    let mut log_path = String::new();
    reader.read_line(&mut log_path)?;
    let log_path = log_path.trim();
    let log_path = if log_path.is_empty() {
        "/var/log/auth.log".to_string()
    } else {
        log_path.to_string()
    };

    // Threshold
    print!("Failed login threshold [5]: ");
    io::stdout().flush()?;
    let mut threshold = String::new();
    reader.read_line(&mut threshold)?;
    let threshold = threshold
        .trim()
        .parse::<u32>()
        .unwrap_or(5);

    // Window size
    print!("Time window in seconds [60]: ");
    io::stdout().flush()?;
    let mut window_secs = String::new();
    reader.read_line(&mut window_secs)?;
    let window_secs = window_secs
        .trim()
        .parse::<u64>()
        .unwrap_or(60);

    // Create and save config
    let config = AgentConfig {
        server_url,
        jwt_token,
        log_path,
        threshold,
        window_secs,
    };

    config.save()?;

    println!("\nConfiguration saved successfully!");
    println!("You can now run: bannkenn-agent run\n");

    Ok(())
}
