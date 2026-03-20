use crate::burst::BurstConfig;
use crate::butterfly::ButterflyShieldConfig;
use crate::campaign::CampaignConfig;
use crate::ebpf::events::ProcessTrustClass;
use crate::event_risk::EventRiskConfig;
use crate::risk_level::RiskLevelConfig;
use crate::shared_risk::SharedRiskSnapshot;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Datelike, Local, NaiveTime, Utc, Weekday};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustPolicyVisibility {
    #[default]
    Visible,
    Hidden,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaintenanceWindow {
    #[serde(default)]
    pub weekdays: Vec<String>,
    pub start: String,
    pub end: String,
}

impl MaintenanceWindow {
    pub fn matches(&self, now: DateTime<Utc>) -> bool {
        let local = now.with_timezone(&Local);
        self.matches_weekday_and_time(local.weekday(), local.time())
    }

    fn matches_weekday_and_time(&self, weekday: Weekday, time: NaiveTime) -> bool {
        let Some(start) = parse_maintenance_time(&self.start) else {
            return false;
        };
        let Some(end) = parse_maintenance_time(&self.end) else {
            return false;
        };
        let weekdays = self.parsed_weekdays();
        let matches_day = |day| match &weekdays {
            Some(days) => days.contains(&day),
            None => true,
        };

        if start == end {
            return matches_day(weekday);
        }

        if start < end {
            matches_day(weekday) && time >= start && time < end
        } else {
            (matches_day(weekday) && time >= start)
                || (matches_day(previous_weekday(weekday)) && time < end)
        }
    }

    fn parsed_weekdays(&self) -> Option<Vec<Weekday>> {
        let specified = self
            .weekdays
            .iter()
            .map(|weekday| weekday.trim())
            .filter(|weekday| !weekday.is_empty())
            .collect::<Vec<_>>();
        if specified.is_empty() {
            None
        } else {
            Some(
                specified
                    .into_iter()
                    .filter_map(parse_weekday)
                    .collect::<Vec<_>>(),
            )
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustPolicyRule {
    pub name: String,
    #[serde(default)]
    pub exe_paths: Vec<String>,
    #[serde(default)]
    pub package_names: Vec<String>,
    #[serde(default)]
    pub service_units: Vec<String>,
    pub trust_class: ProcessTrustClass,
    #[serde(default)]
    pub visibility: TrustPolicyVisibility,
    #[serde(default)]
    pub maintenance_windows: Vec<MaintenanceWindow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainmentConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub dry_run: bool,
    #[serde(default)]
    pub throttle_enabled: bool,
    #[serde(default)]
    pub fuse_enabled: bool,
    #[serde(default = "default_auto_fuse_release_min")]
    pub auto_fuse_release_min: u64,
    #[serde(default = "default_throttle_io_read_bps")]
    pub throttle_io_read_bps: u64,
    #[serde(default = "default_throttle_io_write_bps")]
    pub throttle_io_write_bps: u64,
    #[serde(default = "default_throttle_network_kbit")]
    pub throttle_network_kbit: u32,
    #[serde(default)]
    pub throttle_network_interface: Option<String>,
    #[serde(default = "default_management_allow_ports")]
    pub management_allow_ports: Vec<u16>,
    #[serde(default)]
    pub watch_paths: Vec<String>,
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    #[serde(default)]
    pub protected_paths: Vec<String>,
    #[serde(default = "default_protected_pid_allowlist")]
    pub protected_pid_allowlist: Vec<String>,
    #[serde(default)]
    pub trust_policies: Vec<TrustPolicyRule>,
    #[serde(default)]
    pub ebpf_object_path: Option<String>,
    #[serde(default = "default_ebpf_ringbuf_map")]
    pub ebpf_ringbuf_map: String,
    #[serde(default = "default_suspicious_score")]
    pub suspicious_score: u32,
    #[serde(default = "default_throttle_score")]
    pub throttle_score: u32,
    #[serde(default = "default_fuse_score")]
    pub fuse_score: u32,
    #[serde(default = "default_rename_score")]
    pub rename_score: u32,
    #[serde(default = "default_write_score")]
    pub write_score: u32,
    #[serde(default = "default_delete_score")]
    pub delete_score: u32,
    #[serde(default = "default_protected_path_bonus")]
    pub protected_path_bonus: u32,
    #[serde(default = "default_user_data_bonus")]
    pub user_data_bonus: u32,
    #[serde(default = "default_unknown_process_bonus")]
    pub unknown_process_bonus: u32,
    #[serde(default = "default_trusted_process_penalty")]
    pub trusted_process_penalty: u32,
    #[serde(default = "default_allowed_local_penalty")]
    pub allowed_local_penalty: u32,
    #[serde(default = "default_directory_spread_score")]
    pub directory_spread_score: u32,
    #[serde(default = "default_shell_parent_bonus")]
    pub shell_parent_bonus: u32,
    #[serde(default = "default_recent_process_bonus")]
    pub recent_process_bonus: u32,
    #[serde(default = "default_recent_process_window_secs")]
    pub recent_process_window_secs: u64,
    #[serde(default = "default_bytes_per_score")]
    pub bytes_per_score: u64,
}

impl Default for ContainmentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dry_run: true,
            throttle_enabled: false,
            fuse_enabled: false,
            auto_fuse_release_min: default_auto_fuse_release_min(),
            throttle_io_read_bps: default_throttle_io_read_bps(),
            throttle_io_write_bps: default_throttle_io_write_bps(),
            throttle_network_kbit: default_throttle_network_kbit(),
            throttle_network_interface: None,
            management_allow_ports: default_management_allow_ports(),
            watch_paths: Vec::new(),
            poll_interval_ms: default_poll_interval_ms(),
            protected_paths: Vec::new(),
            protected_pid_allowlist: default_protected_pid_allowlist(),
            trust_policies: Vec::new(),
            ebpf_object_path: None,
            ebpf_ringbuf_map: default_ebpf_ringbuf_map(),
            suspicious_score: default_suspicious_score(),
            throttle_score: default_throttle_score(),
            fuse_score: default_fuse_score(),
            rename_score: default_rename_score(),
            write_score: default_write_score(),
            delete_score: default_delete_score(),
            protected_path_bonus: default_protected_path_bonus(),
            user_data_bonus: default_user_data_bonus(),
            unknown_process_bonus: default_unknown_process_bonus(),
            trusted_process_penalty: default_trusted_process_penalty(),
            allowed_local_penalty: default_allowed_local_penalty(),
            directory_spread_score: default_directory_spread_score(),
            shell_parent_bonus: default_shell_parent_bonus(),
            recent_process_bonus: default_recent_process_bonus(),
            recent_process_window_secs: default_recent_process_window_secs(),
            bytes_per_score: default_bytes_per_score(),
        }
    }
}

/// Agent configuration loaded from TOML file or defaults
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub server_url: String,
    pub jwt_token: String,
    /// Optional PEM certificate/CA bundle used to trust self-signed HTTPS servers.
    #[serde(default)]
    pub ca_cert_path: Option<String>,
    /// Registered name used when connecting to the server (defaults to hostname)
    #[serde(default)]
    pub agent_name: String,
    /// Stable UUID for this agent instance; generated once during `init`
    #[serde(default)]
    pub uuid: String,
    #[serde(default = "default_log_path")]
    pub log_path: String,
    #[serde(default)]
    pub log_paths: Vec<String>,
    #[serde(default = "default_threshold")]
    pub threshold: u32,
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    /// Optional ButterflyShield chaos-based dynamic threshold configuration.
    /// When absent or `enabled = false`, the static `threshold` is used.
    #[serde(default)]
    pub butterfly_shield: Option<ButterflyShieldConfig>,
    /// Optional burst detection configuration.
    /// When absent or `enabled = false`, burst detection is disabled.
    #[serde(default)]
    pub burst: Option<BurstConfig>,
    /// Optional host risk level configuration.
    /// When absent or `enabled = false`, the threshold is not adjusted by history.
    #[serde(default)]
    pub risk_level: Option<RiskLevelConfig>,

    /// Optional event-type risk ranking and surge detection.
    /// When absent or `enabled = false`, all event types are treated equally.
    #[serde(default)]
    pub event_risk: Option<EventRiskConfig>,

    /// Optional local cross-IP campaign correlation.
    /// When absent, runtime defaults enable volume-based campaign correlation.
    /// Set `enabled = false` explicitly to disable it.
    #[serde(default)]
    pub campaign: Option<CampaignConfig>,

    /// Directory containing GeoLite2 `.mmdb` files used by the agent for
    /// GeoIP lookup (country, ASN).  Required for `campaign.geo_grouping`.
    /// If absent, GeoIP features silently degrade to \"Unknown\".
    #[serde(default)]
    pub mmdb_dir: Option<String>,
    /// Optional staged containment/file-activity monitoring configuration.
    /// When absent, runtime defaults keep the feature disabled but configured.
    #[serde(default)]
    pub containment: Option<ContainmentConfig>,
}

fn default_log_path() -> String {
    "/var/log/auth.log".to_string()
}

fn default_threshold() -> u32 {
    5
}

fn default_window_secs() -> u64 {
    60
}

fn default_true() -> bool {
    true
}

fn default_auto_fuse_release_min() -> u64 {
    15
}

fn default_throttle_io_read_bps() -> u64 {
    4 * 1024 * 1024
}

fn default_throttle_io_write_bps() -> u64 {
    1024 * 1024
}

fn default_throttle_network_kbit() -> u32 {
    1024
}

fn default_management_allow_ports() -> Vec<u16> {
    vec![22]
}

fn default_poll_interval_ms() -> u64 {
    1000
}

fn default_suspicious_score() -> u32 {
    30
}

fn default_throttle_score() -> u32 {
    60
}

fn default_fuse_score() -> u32 {
    90
}

fn default_rename_score() -> u32 {
    4
}

fn default_write_score() -> u32 {
    3
}

fn default_delete_score() -> u32 {
    3
}

fn default_protected_path_bonus() -> u32 {
    10
}

fn default_user_data_bonus() -> u32 {
    8
}

fn default_unknown_process_bonus() -> u32 {
    8
}

fn default_trusted_process_penalty() -> u32 {
    6
}

fn default_allowed_local_penalty() -> u32 {
    3
}

fn default_directory_spread_score() -> u32 {
    4
}

fn default_shell_parent_bonus() -> u32 {
    10
}

fn default_recent_process_bonus() -> u32 {
    6
}

fn default_recent_process_window_secs() -> u64 {
    600
}

fn default_bytes_per_score() -> u64 {
    1_048_576
}

fn default_protected_pid_allowlist() -> Vec<String> {
    vec![
        "init".to_string(),
        "systemd".to_string(),
        "sshd".to_string(),
        "bannkenn-agent".to_string(),
    ]
}

fn default_ebpf_ringbuf_map() -> String {
    "BK_EVENTS".to_string()
}

fn parse_maintenance_time(value: &str) -> Option<NaiveTime> {
    NaiveTime::parse_from_str(value.trim(), "%H:%M").ok()
}

fn parse_weekday(value: &str) -> Option<Weekday> {
    match value.trim().to_ascii_lowercase().as_str() {
        "mon" | "monday" => Some(Weekday::Mon),
        "tue" | "tues" | "tuesday" => Some(Weekday::Tue),
        "wed" | "wednesday" => Some(Weekday::Wed),
        "thu" | "thur" | "thurs" | "thursday" => Some(Weekday::Thu),
        "fri" | "friday" => Some(Weekday::Fri),
        "sat" | "saturday" => Some(Weekday::Sat),
        "sun" | "sunday" => Some(Weekday::Sun),
        _ => None,
    }
}

fn previous_weekday(weekday: Weekday) -> Weekday {
    match weekday {
        Weekday::Mon => Weekday::Sun,
        Weekday::Tue => Weekday::Mon,
        Weekday::Wed => Weekday::Tue,
        Weekday::Thu => Weekday::Wed,
        Weekday::Fri => Weekday::Thu,
        Weekday::Sat => Weekday::Fri,
        Weekday::Sun => Weekday::Sat,
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            jwt_token: String::new(),
            ca_cert_path: None,
            agent_name: String::new(),
            uuid: String::new(),
            log_path: default_log_path(),
            log_paths: Vec::new(),
            threshold: default_threshold(),
            window_secs: default_window_secs(),
            butterfly_shield: None,
            burst: None,
            risk_level: None,
            event_risk: None,
            campaign: None,
            mmdb_dir: None,
            containment: None,
        }
    }
}

impl AgentConfig {
    fn apply_runtime_detection_defaults(mut self) -> Self {
        if self.campaign.is_none() {
            self.campaign = Some(default_runtime_campaign_config());
        }
        if self.containment.is_none() {
            self.containment = Some(default_runtime_containment_config());
        }
        self
    }

    /// Load configuration from ~/.config/bannkenn/agent.toml, or return defaults if missing
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;

        if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            let config: AgentConfig = toml::from_str(&content)?;
            Ok(config.apply_runtime_detection_defaults())
        } else {
            Ok(Self::default().apply_runtime_detection_defaults())
        }
    }

    /// Save configuration to ~/.config/bannkenn/agent.toml
    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;

        // Create parent directories if they don't exist
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let toml_string = toml::to_string_pretty(self)?;
        fs::write(&config_path, toml_string)?;

        Ok(())
    }

    fn config_path() -> Result<PathBuf> {
        Ok(state_dir()?.join("agent.toml"))
    }

    /// Backward-compatible view of monitored log paths.
    pub fn effective_log_paths(&self) -> Vec<String> {
        if self.log_paths.is_empty() {
            vec![self.log_path.clone()]
        } else {
            self.log_paths.clone()
        }
    }
}

fn state_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
    Ok(home.join(".config/bannkenn"))
}

pub fn default_runtime_campaign_config() -> CampaignConfig {
    CampaignConfig {
        enabled: true,
        ..Default::default()
    }
}

pub fn default_runtime_containment_config() -> ContainmentConfig {
    ContainmentConfig::default()
}

/// Persistent cursor tracking the last synced decision id
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncState {
    pub last_synced_id: i64,
}

impl SyncState {
    /// Load from `~/.config/bannkenn/sync_state.toml`, or return default if missing
    pub fn load(path: &Path) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|content| toml::from_str(&content).ok())
            .unwrap_or_default()
    }

    /// Persist to `path`
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let toml_string = toml::to_string_pretty(self)?;
        fs::write(path, toml_string)?;
        Ok(())
    }

    pub fn state_path() -> Result<PathBuf> {
        Ok(state_dir()?.join("sync_state.toml"))
    }
}

/// Last-known server-derived data used when the agent is offline.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct OfflineAgentState {
    #[serde(default)]
    pub known_blocked_ips: HashMap<String, String>,
    #[serde(default)]
    pub whitelisted_ips: Vec<String>,
    #[serde(default)]
    pub shared_risk_snapshot: SharedRiskSnapshot,
}

impl OfflineAgentState {
    pub fn load(path: &Path) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|content| toml::from_str(&content).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let toml_string = toml::to_string_pretty(self)?;
        fs::write(path, toml_string)?;
        Ok(())
    }

    pub fn state_path() -> Result<PathBuf> {
        Ok(state_dir()?.join("offline_state.toml"))
    }
}

#[cfg(test)]
#[path = "../tests/unit/config_tests.rs"]
mod tests;
