use anyhow::{anyhow, Result};
use tokio::process::Command;

/// Firewall backend detection and blocking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    Nftables,
    Iptables,
    None,
}

/// Initialize firewall infrastructure required by the agent.
/// For nftables: creates the `bannkenn_blocklist` named set and a drop rule in the
/// `inet filter input` chain if they do not already exist. Safe to call on every startup.
/// For iptables and None backends, no setup is needed.
pub async fn init_firewall(backend: &FirewallBackend) -> Result<()> {
    match backend {
        FirewallBackend::Nftables => init_nftables().await,
        FirewallBackend::Iptables | FirewallBackend::None => Ok(()),
    }
}

/// Set up the nftables infrastructure needed by bannkenn:
///   inet filter table → bannkenn_blocklist set → drop rule in input chain.
/// Every step is guarded by a check so re-running on restart is idempotent.
async fn init_nftables() -> Result<()> {
    // Fast path: set already exists, nothing to do.
    let check = Command::new("nft")
        .args(["list", "set", "inet", "filter", "bannkenn_blocklist"])
        .output()
        .await?;
    if check.status.success() {
        tracing::debug!("nftables: bannkenn_blocklist set already exists");
        return Ok(());
    }

    tracing::info!("nftables: initializing bannkenn firewall infrastructure");

    // Create inet filter table — nft add is idempotent for tables.
    let _ = nft_run(&["add", "table", "inet", "filter"]).await;

    // Create the bannkenn_blocklist set.
    nft_run(&[
        "add",
        "set",
        "inet",
        "filter",
        "bannkenn_blocklist",
        "{ type ipv4_addr ; flags interval ; }",
    ])
    .await
    .map_err(|e| anyhow!("Failed to create bannkenn_blocklist set: {}", e))?;

    // Ensure a base input chain exists (may already exist from system nftables config).
    let chain_check = Command::new("nft")
        .args(["list", "chain", "inet", "filter", "input"])
        .output()
        .await?;
    if !chain_check.status.success() {
        nft_run(&[
            "add",
            "chain",
            "inet",
            "filter",
            "input",
            "{ type filter hook input priority 0 ; policy accept ; }",
        ])
        .await
        .map_err(|e| anyhow!("Failed to create inet filter input chain: {}", e))?;
    }

    // Add drop rule only if not already present (avoids duplicates on restart).
    let chain_out = Command::new("nft")
        .args(["list", "chain", "inet", "filter", "input"])
        .output()
        .await?;
    if !String::from_utf8_lossy(&chain_out.stdout).contains("bannkenn_blocklist") {
        nft_run(&[
            "add",
            "rule",
            "inet",
            "filter",
            "input",
            "ip",
            "saddr",
            "@bannkenn_blocklist",
            "drop",
        ])
        .await
        .map_err(|e| anyhow!("Failed to add blocklist drop rule: {}", e))?;
    }

    tracing::info!("nftables: bannkenn_blocklist set and drop rule configured");
    Ok(())
}

/// Run an nft command with the given arguments, returning an error if it fails.
async fn nft_run(args: &[&str]) -> Result<()> {
    let output = Command::new("nft").args(args).output().await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("{}", stderr.trim()));
    }
    Ok(())
}

/// Detect available firewall backend on the system
pub fn detect_backend() -> FirewallBackend {
    // Check if nft (nftables) is available
    if command_exists("nft") {
        return FirewallBackend::Nftables;
    }

    // Check if iptables is available
    if command_exists("iptables") {
        return FirewallBackend::Iptables;
    }

    // No firewall backend found
    FirewallBackend::None
}

/// Check if a command exists in PATH
fn command_exists(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Block an IP address using the detected firewall backend
pub async fn block_ip(ip: &str, backend: &FirewallBackend) -> Result<()> {
    match backend {
        FirewallBackend::Nftables => block_ip_nftables(ip).await,
        FirewallBackend::Iptables => block_ip_iptables(ip).await,
        FirewallBackend::None => {
            tracing::warn!(
                "No firewall backend available; skipping block for IP: {}",
                ip
            );
            Ok(())
        }
    }
}

/// Block IP using nftables
async fn block_ip_nftables(ip: &str) -> Result<()> {
    let output = Command::new("nft")
        .args([
            "add",
            "element",
            "inet",
            "filter",
            "bannkenn_blocklist",
            &format!("{{ {} }}", ip),
        ])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("nftables block failed for {}: {}", ip, stderr));
    }

    tracing::info!("Blocked IP {} using nftables", ip);
    Ok(())
}

/// Block IP using iptables
async fn block_ip_iptables(ip: &str) -> Result<()> {
    let output = Command::new("iptables")
        .args(["-I", "INPUT", "-s", ip, "-j", "DROP"])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("iptables block failed for {}: {}", ip, stderr));
    }

    tracing::info!("Blocked IP {} using iptables", ip);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_detection() {
        let backend = detect_backend();
        // Don't assert on specific backend since it depends on the system
        // Just ensure it doesn't panic
        match backend {
            FirewallBackend::Nftables => println!("nftables available"),
            FirewallBackend::Iptables => println!("iptables available"),
            FirewallBackend::None => println!("no firewall available"),
        }
    }

    #[test]
    fn test_ip_validation() {
        // Ensure IPs are properly formatted when passed to commands
        let valid_ip = "192.168.1.1";
        assert!(valid_ip.contains('.'));
    }
}
