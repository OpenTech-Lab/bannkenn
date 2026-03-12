use anyhow::{anyhow, Result};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::process::Command;
use tokio::sync::RwLock;

const NFT_FAMILY: &str = "inet";
const NFT_TABLE: &str = "bannkenn";
const NFT_LEGACY_TABLE: &str = "filter";
const NFT_BLOCKLIST_SET: &str = "bannkenn_blocklist";
const NFT_ALLOWLIST_SET: &str = "bannkenn_allowlist";
const NFT_BANNKENN_CHAINS: [&str; 2] = ["input", "forward"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockPattern {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl BlockPattern {
    fn parse(value: &str) -> Option<Self> {
        let (ip_text, prefix_text) = match value.split_once('/') {
            Some((ip, prefix)) => (ip, Some(prefix)),
            None => (value, None),
        };

        match ip_text.parse::<IpAddr>().ok()? {
            IpAddr::V4(ip) => {
                let prefix = match prefix_text {
                    Some(prefix) => prefix.parse::<u8>().ok()?,
                    None => 32,
                };
                if prefix > 32 {
                    return None;
                }
                Some(Self::V4 {
                    network: mask_v4(u32::from(ip), prefix),
                    prefix,
                })
            }
            IpAddr::V6(ip) => {
                let prefix = match prefix_text {
                    Some(prefix) => prefix.parse::<u8>().ok()?,
                    None => 128,
                };
                if prefix > 128 {
                    return None;
                }
                Some(Self::V6 {
                    network: mask_v6(u128::from(ip), prefix),
                    prefix,
                })
            }
        }
    }

    fn render(self) -> String {
        match self {
            Self::V4 { network, prefix } => {
                let ip = Ipv4Addr::from(network);
                if prefix == 32 {
                    ip.to_string()
                } else {
                    format!("{}/{}", ip, prefix)
                }
            }
            Self::V6 { network, prefix } => {
                let ip = Ipv6Addr::from(network);
                if prefix == 128 {
                    ip.to_string()
                } else {
                    format!("{}/{}", ip, prefix)
                }
            }
        }
    }

    fn sort_key(self) -> (u8, u8, u128) {
        match self {
            Self::V4 { network, prefix } => (4, prefix, u128::from(network)),
            Self::V6 { network, prefix } => (6, prefix, network),
        }
    }

    fn covers(self, other: Self) -> bool {
        match (self, other) {
            (
                Self::V4 { network, prefix },
                Self::V4 {
                    network: other_network,
                    prefix: other_prefix,
                },
            ) => prefix <= other_prefix && mask_v4(other_network, prefix) == network,
            (
                Self::V6 { network, prefix },
                Self::V6 {
                    network: other_network,
                    prefix: other_prefix,
                },
            ) => prefix <= other_prefix && mask_v6(other_network, prefix) == network,
            _ => false,
        }
    }

    fn contains_ip(self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4 { network, prefix }, IpAddr::V4(ip)) => {
                mask_v4(u32::from(ip), prefix) == network
            }
            (Self::V6 { network, prefix }, IpAddr::V6(ip)) => {
                mask_v6(u128::from(ip), prefix) == network
            }
            _ => false,
        }
    }

    fn is_local_or_reserved(self) -> bool {
        match self {
            Self::V4 { network, prefix } => {
                let start = Ipv4Addr::from(network);
                let end = Ipv4Addr::from(network | hostmask_v4(prefix));
                should_skip_ipv4_firewall_enforcement(start)
                    && should_skip_ipv4_firewall_enforcement(end)
            }
            Self::V6 { network, prefix } => {
                let start = Ipv6Addr::from(network);
                let end = Ipv6Addr::from(network | hostmask_v6(prefix));
                should_skip_ipv6_firewall_enforcement(end)
                    && should_skip_ipv6_firewall_enforcement(start)
            }
        }
    }
}

fn mask_v4(value: u32, prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else if prefix == 32 {
        value
    } else {
        value & (!0u32 << (32 - prefix))
    }
}

fn hostmask_v4(prefix: u8) -> u32 {
    if prefix == 32 {
        0
    } else {
        !mask_v4(!0u32, prefix)
    }
}

fn mask_v6(value: u128, prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else if prefix == 128 {
        value
    } else {
        value & (!0u128 << (128 - prefix))
    }
}

fn hostmask_v6(prefix: u8) -> u128 {
    if prefix == 128 {
        0
    } else {
        !mask_v6(!0u128, prefix)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FirewallReconcileSummary {
    pub added: u32,
    pub removed: u32,
    pub add_failed: u32,
    pub remove_failed: u32,
}

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
    BlockPattern::parse(ip)
        .map(BlockPattern::is_local_or_reserved)
        .unwrap_or(false)
}

pub fn effective_block_patterns<'a, I>(patterns: I) -> Vec<String>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut parsed = Vec::new();
    let mut opaque = HashSet::new();
    for pattern in patterns {
        if let Some(parsed_pattern) = BlockPattern::parse(pattern) {
            parsed.push(parsed_pattern);
        } else {
            opaque.insert(pattern.to_string());
        }
    }

    parsed.sort_by_key(|pattern| pattern.sort_key());

    let mut effective = Vec::new();
    for pattern in parsed {
        if effective
            .iter()
            .any(|existing: &BlockPattern| existing.covers(pattern))
        {
            continue;
        }
        effective.push(pattern);
    }

    let mut rendered = effective
        .into_iter()
        .map(BlockPattern::render)
        .collect::<Vec<_>>();
    let mut opaque = opaque.into_iter().collect::<Vec<_>>();
    opaque.sort();
    rendered.extend(opaque);
    rendered
}

pub fn block_pattern_covers(pattern: &str, target: &str) -> bool {
    match (BlockPattern::parse(pattern), BlockPattern::parse(target)) {
        (Some(pattern), Some(target)) => pattern.covers(target),
        _ => pattern == target,
    }
}

pub fn block_pattern_matches_ip(pattern: &str, ip: &str) -> bool {
    let Ok(parsed_ip) = ip.parse::<IpAddr>() else {
        return pattern == ip;
    };

    BlockPattern::parse(pattern)
        .map(|pattern| pattern.contains_ip(parsed_ip))
        .unwrap_or(false)
}

pub fn find_matching_block_source(
    known_blocked_ips: &HashMap<String, String>,
    ip: &str,
) -> Option<String> {
    if let Some(source) = known_blocked_ips.get(ip) {
        return Some(source.clone());
    }

    known_blocked_ips.iter().find_map(|(pattern, source)| {
        (pattern.contains('/') && block_pattern_matches_ip(pattern, ip)).then(|| source.clone())
    })
}

pub fn pattern_set_matches_ip(patterns: &HashSet<String>, ip: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| block_pattern_matches_ip(pattern, ip))
}

pub fn pattern_set_covers_pattern(patterns: &HashSet<String>, target: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| block_pattern_covers(pattern, target))
}

pub fn is_block_pattern_effectively_enforced(
    pattern: &str,
    enforced_blocked_ips: &HashSet<String>,
) -> bool {
    enforced_blocked_ips.contains(pattern)
        || enforced_blocked_ips
            .iter()
            .any(|effective| effective.contains('/') && block_pattern_covers(effective, pattern))
}

pub async fn reconcile_block_patterns(
    desired_patterns: &[String],
    enforced_blocked_ips: &Arc<RwLock<HashSet<String>>>,
    backend: &FirewallBackend,
) -> FirewallReconcileSummary {
    let desired = desired_patterns.iter().cloned().collect::<HashSet<_>>();
    let current = enforced_blocked_ips.read().await.clone();
    let mut summary = FirewallReconcileSummary::default();

    let mut removals = current
        .difference(&desired)
        .cloned()
        .collect::<Vec<String>>();
    removals.sort_by(|left, right| sort_block_patterns_specific_first(left, right));

    for pattern in removals {
        match unblock_ip(&pattern, backend).await {
            Ok(_) => {
                enforced_blocked_ips.write().await.remove(&pattern);
                summary.removed += 1;
            }
            Err(err) => {
                tracing::warn!(
                    "firewall: failed to remove superseded block pattern {}: {}",
                    pattern,
                    err
                );
                summary.remove_failed += 1;
            }
        }
    }

    let current = enforced_blocked_ips.read().await.clone();
    for pattern in desired_patterns {
        if current.contains(pattern) {
            continue;
        }

        match block_ip(pattern, backend).await {
            Ok(_) => {
                enforced_blocked_ips.write().await.insert(pattern.clone());
                summary.added += 1;
            }
            Err(err) => {
                tracing::warn!(
                    "firewall: failed to enforce desired block pattern {}: {}",
                    pattern,
                    err
                );
                summary.add_failed += 1;
            }
        }
    }

    summary
}

pub async fn reconcile_whitelist_ips(
    desired_patterns: &[String],
    enforced_whitelisted_ips: &Arc<RwLock<HashSet<String>>>,
    backend: &FirewallBackend,
) -> FirewallReconcileSummary {
    let desired_ips = desired_patterns.iter().cloned().collect::<HashSet<_>>();
    let current = enforced_whitelisted_ips.read().await.clone();
    let mut summary = FirewallReconcileSummary::default();

    let mut removals = current
        .difference(&desired_ips)
        .cloned()
        .collect::<Vec<String>>();
    removals.sort_by(|left, right| sort_block_patterns_specific_first(left, right));

    for ip in removals {
        match unallow_ip(&ip, backend).await {
            Ok(_) => {
                enforced_whitelisted_ips.write().await.remove(&ip);
                summary.removed += 1;
            }
            Err(err) => {
                tracing::warn!(
                    "firewall: failed to remove whitelist override for {}: {}",
                    ip,
                    err
                );
                summary.remove_failed += 1;
            }
        }
    }

    let current = enforced_whitelisted_ips.read().await.clone();
    let additions = desired_patterns.to_vec();
    for ip in additions {
        if current.contains(&ip) {
            continue;
        }

        match allow_ip(&ip, backend).await {
            Ok(_) => {
                enforced_whitelisted_ips.write().await.insert(ip.clone());
                summary.added += 1;
            }
            Err(err) => {
                tracing::warn!(
                    "firewall: failed to enforce whitelist override for {}: {}",
                    ip,
                    err
                );
                summary.add_failed += 1;
            }
        }
    }

    summary
}

fn sort_block_patterns_specific_first(left: &str, right: &str) -> Ordering {
    match (BlockPattern::parse(left), BlockPattern::parse(right)) {
        (Some(left), Some(right)) => right
            .sort_key()
            .1
            .cmp(&left.sort_key().1)
            .then_with(|| left.sort_key().0.cmp(&right.sort_key().0))
            .then_with(|| left.sort_key().2.cmp(&right.sort_key().2))
            .then_with(|| left.render().cmp(&right.render())),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => left.cmp(right),
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

    // Ensure the shared allow/block sets exist.
    ensure_nft_set(
        NFT_TABLE,
        NFT_ALLOWLIST_SET,
        "{ type ipv4_addr ; flags interval ; }",
    )
    .await?;
    ensure_nft_set(
        NFT_TABLE,
        NFT_BLOCKLIST_SET,
        "{ type ipv4_addr ; flags interval ; }",
    )
    .await?;

    ensure_nft_chain(NFT_TABLE, "input", "input").await?;
    ensure_nft_chain(NFT_TABLE, "forward", "forward").await?;
    ensure_nft_allow_rule(NFT_TABLE, "input").await?;
    ensure_nft_allow_rule(NFT_TABLE, "forward").await?;
    ensure_nft_drop_rule(NFT_TABLE, "input").await?;
    ensure_nft_drop_rule(NFT_TABLE, "forward").await?;

    tracing::info!(
        "nftables: {} table, {} + {} sets, and allow/drop rules configured",
        NFT_TABLE,
        NFT_ALLOWLIST_SET,
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

async fn ensure_nft_set(table: &str, set_name: &str, definition: &str) -> Result<()> {
    let set_check = Command::new("nft")
        .args(["list", "set", NFT_FAMILY, table, set_name])
        .output()
        .await?;
    if !set_check.status.success() {
        nft_run(&["add", "set", NFT_FAMILY, table, set_name, definition])
            .await
            .map_err(|e| anyhow!("Failed to create {} set in {}: {}", set_name, table, e))?;
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

async fn ensure_nft_allow_rule(table: &str, chain: &str) -> Result<()> {
    let chain_out = Command::new("nft")
        .args(["list", "chain", NFT_FAMILY, table, chain])
        .output()
        .await?;
    if !String::from_utf8_lossy(&chain_out.stdout).contains(NFT_ALLOWLIST_SET) {
        nft_run(&[
            "insert",
            "rule",
            NFT_FAMILY,
            table,
            chain,
            "ip",
            "saddr",
            &format!("@{}", NFT_ALLOWLIST_SET),
            "accept",
            "comment",
            "bannkenn-managed",
        ])
        .await
        .map_err(|e| {
            anyhow!(
                "Failed to add allowlist accept rule to {} {}: {}",
                table,
                chain,
                e
            )
        })?;
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

/// Add an IP address to the active firewall allowlist so it bypasses BannKenn drops.
pub async fn allow_ip(ip: &str, backend: &FirewallBackend) -> Result<()> {
    if should_skip_local_firewall_enforcement(ip) {
        return Ok(());
    }

    match backend {
        FirewallBackend::Nftables => allow_ip_nftables(ip).await,
        FirewallBackend::Iptables => allow_ip_iptables(ip).await,
        FirewallBackend::None => Ok(()),
    }
}

/// Remove an IP address from the active firewall allowlist.
pub async fn unallow_ip(ip: &str, backend: &FirewallBackend) -> Result<()> {
    match backend {
        FirewallBackend::Nftables => unallow_ip_nftables(ip).await,
        FirewallBackend::Iptables => unallow_ip_iptables(ip).await,
        FirewallBackend::None => Ok(()),
    }
}

/// Remove an IP address from the active firewall backend.
pub async fn unblock_ip(ip: &str, backend: &FirewallBackend) -> Result<()> {
    match backend {
        FirewallBackend::Nftables => unblock_ip_nftables(ip).await,
        FirewallBackend::Iptables => unblock_ip_iptables(ip).await,
        FirewallBackend::None => Ok(()),
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

async fn allow_ip_nftables(ip: &str) -> Result<()> {
    let output = Command::new("nft")
        .args([
            "add",
            "element",
            NFT_FAMILY,
            NFT_TABLE,
            NFT_ALLOWLIST_SET,
            &format!("{{ {} }}", ip),
        ])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("File exists") {
            tracing::debug!("IP {} already present in nftables allowlist", ip);
            return Ok(());
        }
        return Err(anyhow!("nftables allowlist failed for {}: {}", ip, stderr));
    }

    tracing::info!("Allowed IP {} using nftables", ip);
    Ok(())
}

async fn unallow_ip_nftables(ip: &str) -> Result<()> {
    let output = Command::new("nft")
        .args([
            "delete",
            "element",
            NFT_FAMILY,
            NFT_TABLE,
            NFT_ALLOWLIST_SET,
            &format!("{{ {} }}", ip),
        ])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_nft_missing_error(&stderr) || stderr.contains("No such file or directory") {
            return Ok(());
        }
        return Err(anyhow!(
            "nftables allowlist removal failed for {}: {}",
            ip,
            stderr
        ));
    }

    tracing::info!("Removed IP {} from nftables allowlist", ip);
    Ok(())
}

async fn unblock_ip_nftables(ip: &str) -> Result<()> {
    let output = Command::new("nft")
        .args([
            "delete",
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
        if is_nft_missing_error(&stderr) || stderr.contains("No such file or directory") {
            return Ok(());
        }
        return Err(anyhow!("nftables unblock failed for {}: {}", ip, stderr));
    }

    tracing::info!("Unblocked IP {} using nftables", ip);
    Ok(())
}

/// Block IP using iptables
async fn block_ip_iptables(ip: &str) -> Result<()> {
    ensure_iptables_drop("INPUT", ip).await?;
    ensure_iptables_drop("FORWARD", ip).await?;

    tracing::info!("Blocked IP {} using iptables", ip);
    Ok(())
}

async fn allow_ip_iptables(ip: &str) -> Result<()> {
    ensure_iptables_accept("INPUT", ip).await?;
    ensure_iptables_accept("FORWARD", ip).await?;

    tracing::info!("Allowed IP {} using iptables", ip);
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

async fn ensure_iptables_accept(chain: &str, ip: &str) -> Result<()> {
    let check = Command::new("iptables")
        .args(["-C", chain, "-s", ip, "-j", "ACCEPT"])
        .output()
        .await?;
    if check.status.success() {
        return Ok(());
    }

    let output = Command::new("iptables")
        .args(["-I", chain, "1", "-s", ip, "-j", "ACCEPT"])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "iptables allow failed for {} in {}: {}",
            ip,
            chain,
            stderr
        ));
    }

    Ok(())
}

async fn unblock_ip_iptables(ip: &str) -> Result<()> {
    remove_iptables_drop("INPUT", ip).await?;
    remove_iptables_drop("FORWARD", ip).await?;

    tracing::info!("Unblocked IP {} using iptables", ip);
    Ok(())
}

async fn unallow_ip_iptables(ip: &str) -> Result<()> {
    remove_iptables_accept("INPUT", ip).await?;
    remove_iptables_accept("FORWARD", ip).await?;

    tracing::info!("Removed IP {} from iptables allowlist", ip);
    Ok(())
}

async fn remove_iptables_drop(chain: &str, ip: &str) -> Result<()> {
    let check = Command::new("iptables")
        .args(["-C", chain, "-s", ip, "-j", "DROP"])
        .output()
        .await?;
    if !check.status.success() {
        return Ok(());
    }

    let output = Command::new("iptables")
        .args(["-D", chain, "-s", ip, "-j", "DROP"])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "iptables unblock failed for {} in {}: {}",
            ip,
            chain,
            stderr
        ));
    }

    Ok(())
}

async fn remove_iptables_accept(chain: &str, ip: &str) -> Result<()> {
    let check = Command::new("iptables")
        .args(["-C", chain, "-s", ip, "-j", "ACCEPT"])
        .output()
        .await?;
    if !check.status.success() {
        return Ok(());
    }

    let output = Command::new("iptables")
        .args(["-D", chain, "-s", ip, "-j", "ACCEPT"])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "iptables allow removal failed for {} in {}: {}",
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

    #[test]
    fn effective_block_patterns_collapse_overlapping_hosts_and_cidrs() {
        let effective = effective_block_patterns([
            "101.47.142.48",
            "101.47.142.0/24",
            "193.32.162.17",
            "193.32.162.0/24",
            "8.8.8.8",
        ]);

        assert_eq!(
            effective,
            vec![
                "101.47.142.0/24".to_string(),
                "193.32.162.0/24".to_string(),
                "8.8.8.8".to_string(),
            ]
        );
    }

    #[test]
    fn effective_enforcement_recognizes_cidr_coverage() {
        let enforced =
            HashSet::from(["101.47.142.0/24".to_string(), "193.32.162.0/24".to_string()]);

        assert!(is_block_pattern_effectively_enforced(
            "101.47.142.48",
            &enforced
        ));
        assert!(is_block_pattern_effectively_enforced(
            "193.32.162.0/24",
            &enforced
        ));
        assert!(!is_block_pattern_effectively_enforced("8.8.8.8", &enforced));
    }

    #[test]
    fn source_matching_supports_cidr_patterns() {
        let known = HashMap::from([
            ("203.0.113.0/24".to_string(), "feed".to_string()),
            ("198.51.100.77".to_string(), "agent".to_string()),
        ]);

        assert_eq!(
            find_matching_block_source(&known, "203.0.113.9"),
            Some("feed".to_string())
        );
        assert_eq!(
            find_matching_block_source(&known, "198.51.100.77"),
            Some("agent".to_string())
        );
        assert_eq!(find_matching_block_source(&known, "198.51.100.78"), None);
    }

    #[test]
    fn local_cidr_patterns_are_skipped() {
        assert!(should_skip_local_firewall_enforcement("10.0.0.0/24"));
        assert!(should_skip_local_firewall_enforcement("fc00::/7"));
        assert!(!should_skip_local_firewall_enforcement("11.0.0.0/8"));
    }

    #[test]
    fn pattern_sets_match_ips_and_cover_patterns() {
        let patterns = HashSet::from(["203.0.113.0/24".to_string(), "198.51.100.77".to_string()]);

        assert!(pattern_set_matches_ip(&patterns, "203.0.113.99"));
        assert!(pattern_set_matches_ip(&patterns, "198.51.100.77"));
        assert!(!pattern_set_matches_ip(&patterns, "198.51.100.78"));
        assert!(pattern_set_covers_pattern(&patterns, "203.0.113.0/25"));
        assert!(!pattern_set_covers_pattern(&patterns, "203.0.112.0/24"));
    }

    #[tokio::test]
    async fn whitelist_reconcile_tracks_exact_ip_and_cidr_overrides() {
        let desired = vec!["203.0.113.0/24".to_string(), "198.51.100.77".to_string()];
        let enforced = Arc::new(RwLock::new(HashSet::from(["198.51.100.7".to_string()])));

        let summary = reconcile_whitelist_ips(&desired, &enforced, &FirewallBackend::None).await;

        assert_eq!(summary.added, 2);
        assert_eq!(summary.removed, 1);
        assert_eq!(summary.add_failed, 0);
        assert_eq!(summary.remove_failed, 0);
        assert_eq!(*enforced.read().await, desired.into_iter().collect());
    }
}
