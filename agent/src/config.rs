use crate::butterfly::ButterflyShieldConfig;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
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
    #[serde(default = "default_threshold")]
    pub threshold: u32,
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    /// Optional ButterflyShield chaos-based dynamic threshold configuration.
    /// When absent or `enabled = false`, the static `threshold` is used.
    #[serde(default)]
    pub butterfly_shield: Option<ButterflyShieldConfig>,
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
            threshold: default_threshold(),
            window_secs: default_window_secs(),
            butterfly_shield: None,
        }
    }
}

impl AgentConfig {
    /// Load configuration from ~/.config/bannkenn/agent.toml, or return defaults if missing
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;

        if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            let config: AgentConfig = toml::from_str(&content)?;
            Ok(config)
        } else {
            Ok(Self::default())
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
        let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
        Ok(home.join(".config/bannkenn/agent.toml"))
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
        let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
        Ok(home.join(".config/bannkenn/sync_state.toml"))
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
            threshold: 3,
            window_secs: 120,
            butterfly_shield: None,
        };

        let toml_str = toml::to_string(&config).unwrap();
        let deserialized: AgentConfig = toml::from_str(&toml_str).unwrap();

        assert_eq!(config.server_url, deserialized.server_url);
        assert_eq!(config.jwt_token, deserialized.jwt_token);
        assert_eq!(config.threshold, deserialized.threshold);
    }
}
