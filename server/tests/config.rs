use bannkenn_server::config::{ServerConfig, ServerTlsConfig};

#[test]
fn default_config_matches_expected_defaults() {
    let config = ServerConfig::default();

    assert_eq!(config.bind, "0.0.0.0:3022");
    assert_eq!(config.local_bind, None);
    assert_eq!(config.db_path, "bannkenn.db");
    assert_eq!(config.behavior_pg_url, None);
    assert_eq!(config.jwt_secret, "change-me-in-production");
    assert_eq!(config.tls_cert_path, None);
    assert_eq!(config.tls_key_path, None);
}

#[test]
fn tls_config_accepts_complete_pair() {
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
fn tls_config_requires_both_paths() {
    let config = ServerConfig {
        tls_cert_path: Some("/etc/bannkenn/tls/server.crt".to_string()),
        ..ServerConfig::default()
    };

    assert!(config.tls_config().is_err());
}
