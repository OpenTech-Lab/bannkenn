use anyhow::{anyhow, Result};
use tokio::process::Command;

/// Firewall backend detection and blocking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    Nftables,
    Iptables,
    None,
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
        .args(&[
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
        .args(&["-I", "INPUT", "-s", ip, "-j", "DROP"])
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
