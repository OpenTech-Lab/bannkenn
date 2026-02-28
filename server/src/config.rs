use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind: String,
    pub db_path: String,
    pub jwt_secret: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:3022".to_string(),
            db_path: "bannkenn.db".to_string(),
            jwt_secret: "change-me-in-production".to_string(),
        }
    }
}

impl ServerConfig {
    pub fn load() -> anyhow::Result<ServerConfig> {
        // Try to load from server.toml in current directory
        if let Ok(contents) = fs::read_to_string("server.toml") {
            let config: ServerConfig = toml::from_str(&contents)?;
            return Ok(config);
        }

        // Try to load from environment variables
        let mut config = ServerConfig::default();

        if let Ok(bind) = std::env::var("BANNKENN_BIND") {
            config.bind = bind;
        }

        if let Ok(db_path) = std::env::var("BANNKENN_DB_PATH") {
            config.db_path = db_path;
        }

        if let Ok(jwt_secret) = std::env::var("BANNKENN_JWT_SECRET") {
            config.jwt_secret = jwt_secret;
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert_eq!(config.bind, "0.0.0.0:3022");
        assert_eq!(config.db_path, "bannkenn.db");
        assert_eq!(config.jwt_secret, "change-me-in-production");
    }
}
