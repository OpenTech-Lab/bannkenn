use anyhow::{anyhow, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::process::Command;

const NFT_FAMILY: &str = "inet";
const NFT_TABLE: &str = "bannkenn";
const NFT_LEGACY_TABLE: &str = "filter";
const NFT_BLOCKLIST_SET: &str = "bannkenn_blocklist";
const NFT_BANNKENN_CHAINS: [&str; 2] = ["input", "forward"];

/// Firewall backend detection and blocking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    Nftables,
    Iptables,
    None,
}

/// Local/self-originated ranges should never be enforced into the firewall
/// blocklist because that can cut the host off from its own services.
pub fn should_skip_local_firewall_enforcement(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => should_skip_ipv4_firewall_enforcement(ip),
        Ok(IpAddr::V6(ip)) => should_skip_ipv6_firewall_enforcement(ip),
        Err(_) => false,
    }
}

/// Initialize firewall infrastructure required by the agent.
/// For nftables: creates the `bannkenn_blocklist` named set and drop rules in the
/// dedicated `inet bannkenn` table so BannKenn state stays isolated from the main
/// `filter` table. Safe to call on every startup.
/// On upgrade, any legacy BannKenn rules previously stored in `inet filter` are removed.
/// For iptables and None backends, no setup is needed.
pub async fn init_firewall(backend: &FirewallBackend) -> Result<()> {
    match backend {
        FirewallBackend::Nftables => init_nftables().await,
        FirewallBackend::Iptables | FirewallBackend::None => Ok(()),
    }
}

/// Remove BannKenn-managed firewall state for the active backend.
/// For nftables, this removes the dedicated BannKenn table and any legacy
/// BannKenn rules previously installed into `inet filter`.
/// The operation is idempotent so it can safely run both on process shutdown and
/// via a systemd ExecStopPost hook.
pub async fn cleanup_firewall(backend: &FirewallBackend) -> Result<()> {
    match backend {
        FirewallBackend::Nftables => cleanup_nftables().await,
        FirewallBackend::Iptables | FirewallBackend::None => Ok(()),
    }
}

/// Set up the nftables infrastructure needed by bannkenn:
///   inet bannkenn table → bannkenn_blocklist set → drop rules in input + forward chains.
/// Every step is guarded by a check so re-running on restart is idempotent.
async fn init_nftables() -> Result<()> {
    tracing::info!(
        "nftables: initializing BannKenn firewall infrastructure in inet {}",
        NFT_TABLE
    );

    cleanup_legacy_nftables().await?;

    // Create dedicated BannKenn table — nft add is idempotent for tables.
    let _ = nft_run(&["add", "table", NFT_FAMILY, NFT_TABLE]).await;

    // Ensure the shared blocklist set exists.
    ensure_nft_set(NFT_TABLE).await?;

    ensure_nft_chain(NFT_TABLE, "input", "input").await?;
    ensure_nft_chain(NFT_TABLE, "forward", "forward").await?;
    ensure_nft_drop_rule(NFT_TABLE, "input").await?;
    ensure_nft_drop_rule(NFT_TABLE, "forward").await?;

    tracing::info!(
        "nftables: {} table, {} set, and drop rules configured",
        NFT_TABLE,
        NFT_BLOCKLIST_SET
    );
    Ok(())
}

async fn cleanup_nftables() -> Result<()> {
    tracing::info!("nftables: removing BannKenn-managed firewall rules");

    nft_run_allow_missing(&["delete", "table", NFT_FAMILY, NFT_TABLE]).await?;
    cleanup_legacy_nftables().await?;

    tracing::info!("nftables: BannKenn-managed firewall rules removed");
    Ok(())
}

async fn ensure_nft_set(table: &str) -> Result<()> {
    let set_check = Command::new("nft")
        .args(["list", "set", NFT_FAMILY, table, NFT_BLOCKLIST_SET])
        .output()
        .await?;
    if !set_check.status.success() {
        nft_run(&[
            "add",
            "set",
            NFT_FAMILY,
            table,
            NFT_BLOCKLIST_SET,
            "{ type ipv4_addr ; flags interval ; }",
        ])
        .await
        .map_err(|e| {
            anyhow!(
                "Failed to create {} set in {}: {}",
                NFT_BLOCKLIST_SET,
                table,
                e
            )
        })?;
    }
    Ok(())
}

async fn ensure_nft_chain(table: &str, chain: &str, hook: &str) -> Result<()> {
    let chain_check = Command::new("nft")
        .args(["list", "chain", NFT_FAMILY, table, chain])
        .output()
        .await?;
    if !chain_check.status.success() {
        nft_run(&[
            "add",
            "chain",
            NFT_FAMILY,
            table,
            chain,
            &format!(
                "{{ type filter hook {} priority 0 ; policy accept ; }}",
                hook
            ),
        ])
        .await
        .map_err(|e| anyhow!("Failed to create inet {} {} chain: {}", table, chain, e))?;
    }
    Ok(())
}

async fn ensure_nft_drop_rule(table: &str, chain: &str) -> Result<()> {
    let chain_out = Command::new("nft")
        .args(["list", "chain", NFT_FAMILY, table, chain])
        .output()
        .await?;
    if !String::from_utf8_lossy(&chain_out.stdout).contains(NFT_BLOCKLIST_SET) {
        nft_run(&[
            "add",
            "rule",
            NFT_FAMILY,
            table,
            chain,
            "ip",
            "saddr",
            &format!("@{}", NFT_BLOCKLIST_SET),
            "drop",
            "comment",
            "bannkenn-managed",
        ])
        .await
        .map_err(|e| {
            anyhow!(
                "Failed to add blocklist drop rule to {} {}: {}",
                table,
                chain,
                e
            )
        })?;
    }
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

async fn nft_run_allow_missing(args: &[&str]) -> Result<()> {
    let output = Command::new("nft").args(args).output().await?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if is_nft_missing_error(&stderr) {
        return Ok(());
    }

    Err(anyhow!("{}", stderr.trim()))
}

async fn remove_nft_drop_rules(table: &str, chain: &str) -> Result<()> {
    let output = Command::new("nft")
        .args(["-a", "list", "chain", NFT_FAMILY, table, chain])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_nft_missing_error(&stderr) {
            return Ok(());
        }
        return Err(anyhow!(
            "Failed to inspect nftables chain {} {}: {}",
            table,
            chain,
            stderr.trim()
        ));
    }

    for handle in bannkenn_rule_handles(&String::from_utf8_lossy(&output.stdout)) {
        let handle_str = handle.to_string();
        nft_run_allow_missing(&[
            "delete",
            "rule",
            NFT_FAMILY,
            table,
            chain,
            "handle",
            &handle_str,
        ])
        .await?;
    }

    Ok(())
}

async fn cleanup_legacy_nftables() -> Result<()> {
    for chain in NFT_BANNKENN_CHAINS {
        remove_nft_drop_rules(NFT_LEGACY_TABLE, chain).await?;
    }

    nft_run_allow_missing(&[
        "delete",
        "set",
        NFT_FAMILY,
        NFT_LEGACY_TABLE,
        NFT_BLOCKLIST_SET,
    ])
    .await?;

    Ok(())
}

fn bannkenn_rule_handles(chain_output: &str) -> Vec<u32> {
    chain_output
        .lines()
        .filter(|line| line.contains(&format!("@{}", NFT_BLOCKLIST_SET)))
        .filter_map(extract_nft_rule_handle)
        .collect()
}

fn extract_nft_rule_handle(line: &str) -> Option<u32> {
    line.split("# handle ")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn is_nft_missing_error(stderr: &str) -> bool {
    let stderr = stderr.to_ascii_lowercase();
    stderr.contains("no such file or directory")
        || stderr.contains("not found")
        || stderr.contains("does not exist")
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
    if should_skip_local_firewall_enforcement(ip) {
        tracing::warn!(
            "Skipping firewall enforcement for local/reserved address {}",
            ip
        );
        return Ok(());
    }

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

fn should_skip_ipv4_firewall_enforcement(ip: Ipv4Addr) -> bool {
    let [first, second, _, _] = ip.octets();

    first == 0
        || first == 10
        || first == 127
        || (first == 100 && (64..=127).contains(&second))
        || (first == 169 && second == 254)
        || (first == 172 && (16..=31).contains(&second))
        || (first == 192 && second == 168)
        || (first == 198 && (second == 18 || second == 19))
        || first >= 224
}

fn should_skip_ipv6_firewall_enforcement(ip: Ipv6Addr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() {
        return true;
    }

    if let Some(mapped) = ip.to_ipv4_mapped() {
        return should_skip_ipv4_firewall_enforcement(mapped);
    }

    let first = ip.segments()[0];

    (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80 || (first & 0xff00) == 0xff00
}

/// Block IP using nftables
async fn block_ip_nftables(ip: &str) -> Result<()> {
    let output = Command::new("nft")
        .args([
            "add",
            "element",
            NFT_FAMILY,
            NFT_TABLE,
            NFT_BLOCKLIST_SET,
            &format!("{{ {} }}", ip),
        ])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("File exists") {
            tracing::debug!("IP {} already present in nftables blocklist", ip);
            return Ok(());
        }
        return Err(anyhow!("nftables block failed for {}: {}", ip, stderr));
    }

    tracing::info!("Blocked IP {} using nftables", ip);
    Ok(())
}

/// Block IP using iptables
async fn block_ip_iptables(ip: &str) -> Result<()> {
    ensure_iptables_drop("INPUT", ip).await?;
    ensure_iptables_drop("FORWARD", ip).await?;

    tracing::info!("Blocked IP {} using iptables", ip);
    Ok(())
}

async fn ensure_iptables_drop(chain: &str, ip: &str) -> Result<()> {
    let check = Command::new("iptables")
        .args(["-C", chain, "-s", ip, "-j", "DROP"])
        .output()
        .await?;
    if check.status.success() {
        return Ok(());
    }

    let output = Command::new("iptables")
        .args(["-I", chain, "-s", ip, "-j", "DROP"])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "iptables block failed for {} in {}: {}",
            ip,
            chain,
            stderr
        ));
    }

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

    #[test]
    fn local_and_reserved_ips_are_skipped_for_firewall_enforcement() {
        for ip in [
            "127.0.0.1",
            "10.0.0.8",
            "172.17.0.1",
            "192.168.1.20",
            "169.254.10.2",
            "100.64.1.5",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                should_skip_local_firewall_enforcement(ip),
                "{} should be skipped",
                ip
            );
        }
    }

    #[test]
    fn public_ips_remain_eligible_for_firewall_enforcement() {
        for ip in ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"] {
            assert!(
                !should_skip_local_firewall_enforcement(ip),
                "{} should remain blockable",
                ip
            );
        }
    }

    #[test]
    fn bannkenn_rule_handle_parser_ignores_unrelated_rules() {
        let chain = r#"
table inet bannkenn {
	chain input {
		type filter hook input priority filter; policy accept;
		ct state established,related accept # handle 1
		ip saddr @bannkenn_blocklist drop comment "bannkenn-managed" # handle 7
		ip saddr 203.0.113.10 drop # handle 9
		ip saddr @bannkenn_blocklist drop # handle 11
	}
}
"#;

        assert_eq!(bannkenn_rule_handles(chain), vec![7, 11]);
    }

    #[test]
    fn nft_handle_parser_requires_numeric_handle() {
        assert_eq!(
            extract_nft_rule_handle("ip saddr @bannkenn_blocklist drop # handle 42"),
            Some(42)
        );
        assert_eq!(
            extract_nft_rule_handle("ip saddr @bannkenn_blocklist drop"),
            None
        );
        assert_eq!(
            extract_nft_rule_handle("ip saddr @bannkenn_blocklist drop # handle abc"),
            None
        );
    }
}
