use crate::shared_risk::SharedRiskSnapshot;
use crate::burst::BurstConfig;
use crate::butterfly::ButterflyShieldConfig;
use crate::campaign::CampaignConfig;
use crate::event_risk::EventRiskConfig;
use crate::risk_level::RiskLevelConfig;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Agent configuration loaded from TOML file or defaults
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub server_url: String,
    pub jwt_token: String,
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

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            jwt_token: String::new(),
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
        }
    }
}

impl AgentConfig {
    fn apply_runtime_detection_defaults(mut self) -> Self {
        if self.campaign.is_none() {
            self.campaign = Some(default_runtime_campaign_config());
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
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AgentConfig::default();
        assert_eq!(config.log_path, "/var/log/auth.log");
        assert_eq!(config.threshold, 5);
        assert_eq!(config.window_secs, 60);
    }

    #[test]
    fn test_config_serialization() {
        let config = AgentConfig {
            server_url: "http://localhost:8080".to_string(),
            jwt_token: "token123".to_string(),
            agent_name: "test-agent".to_string(),
            uuid: "test-uuid".to_string(),
            log_path: "/var/log/auth.log".to_string(),
            log_paths: vec!["/var/log/auth.log".to_string()],
            threshold: 3,
            window_secs: 120,
            butterfly_shield: None,
            burst: None,
            risk_level: None,
            event_risk: None,
            campaign: None,
            mmdb_dir: None,
        };

        let toml_str = toml::to_string(&config).unwrap();
        let deserialized: AgentConfig = toml::from_str(&toml_str).unwrap();

        assert_eq!(config.server_url, deserialized.server_url);
        assert_eq!(config.jwt_token, deserialized.jwt_token);
        assert_eq!(config.threshold, deserialized.threshold);
    }

    #[test]
    fn runtime_defaults_enable_campaign_when_missing() {
        let config = AgentConfig::default().apply_runtime_detection_defaults();
        let campaign = config
            .campaign
            .expect("runtime defaults should populate campaign config");
        assert!(campaign.enabled);
        assert_eq!(campaign.distinct_ips_threshold, 3);
    }

    #[test]
    fn offline_agent_state_round_trips() {
        let dir = std::env::temp_dir().join(format!("bannkenn-offline-state-{}", uuid::Uuid::new_v4()));
        let path = dir.join("offline.toml");
        let state = OfflineAgentState {
            known_blocked_ips: HashMap::from([("203.0.113.10".to_string(), "agent".to_string())]),
            shared_risk_snapshot: SharedRiskSnapshot {
                generated_at: "2026-03-10T00:00:00Z".to_string(),
                window_secs: 600,
                global_risk_score: 0.8,
                global_threshold_multiplier: 0.6,
                categories: Vec::new(),
            },
        };

        state.save(&path).unwrap();
        let loaded = OfflineAgentState::load(&path);
        assert_eq!(loaded, state);

        let _ = fs::remove_dir_all(dir);
    }
}
