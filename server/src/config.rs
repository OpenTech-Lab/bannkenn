use anyhow::bail;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind: String,
    pub local_bind: Option<String>,
    pub db_path: String,
    pub jwt_secret: String,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerTlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:3022".to_string(),
            local_bind: None,
            db_path: "bannkenn.db".to_string(),
            jwt_secret: "change-me-in-production".to_string(),
            tls_cert_path: None,
            tls_key_path: None,
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

        if let Ok(local_bind) = std::env::var("BANNKENN_LOCAL_BIND") {
            config.local_bind = normalize_optional_string(Some(local_bind));
        }

        if let Ok(db_path) = std::env::var("BANNKENN_DB_PATH") {
            config.db_path = db_path;
        }

        if let Ok(jwt_secret) = std::env::var("BANNKENN_JWT_SECRET") {
            config.jwt_secret = jwt_secret;
        }

        if let Ok(tls_cert_path) = std::env::var("BANNKENN_TLS_CERT_PATH") {
            config.tls_cert_path = normalize_optional_string(Some(tls_cert_path));
        }

        if let Ok(tls_key_path) = std::env::var("BANNKENN_TLS_KEY_PATH") {
            config.tls_key_path = normalize_optional_string(Some(tls_key_path));
        }

        Ok(config)
    }

    pub fn tls_config(&self) -> anyhow::Result<Option<ServerTlsConfig>> {
        let cert_path = normalize_optional_string(self.tls_cert_path.clone());
        let key_path = normalize_optional_string(self.tls_key_path.clone());

        match (cert_path, key_path) {
            (None, None) => Ok(None),
            (Some(cert_path), Some(key_path)) => Ok(Some(ServerTlsConfig {
                cert_path,
                key_path,
            })),
            _ => bail!("both tls_cert_path and tls_key_path must be set together"),
        }
    }
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert_eq!(config.bind, "0.0.0.0:3022");
        assert_eq!(config.local_bind, None);
        assert_eq!(config.db_path, "bannkenn.db");
        assert_eq!(config.jwt_secret, "change-me-in-production");
        assert_eq!(config.tls_cert_path, None);
        assert_eq!(config.tls_key_path, None);
    }

    #[test]
    fn test_tls_config_accepts_complete_pair() {
        let config = ServerConfig {
            tls_cert_path: Some("/etc/bannkenn/tls/server.crt".to_string()),
            tls_key_path: Some("/etc/bannkenn/tls/server.key".to_string()),
            ..ServerConfig::default()
        };

        assert_eq!(
            config.tls_config().unwrap(),
            Some(ServerTlsConfig {
                cert_path: "/etc/bannkenn/tls/server.crt".to_string(),
                key_path: "/etc/bannkenn/tls/server.key".to_string(),
            })
        );
    }

    #[test]
    fn test_tls_config_requires_both_paths() {
        let config = ServerConfig {
            tls_cert_path: Some("/etc/bannkenn/tls/server.crt".to_string()),
            ..ServerConfig::default()
        };

        assert!(config.tls_config().is_err());
    }
}
