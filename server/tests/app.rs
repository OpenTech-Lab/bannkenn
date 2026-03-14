use bannkenn_server::{
    app::{healthcheck_target, healthcheck_url, listener_addresses_conflict, parse_optional_bind},
    config::ServerConfig,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[test]
fn parse_optional_bind_treats_blank_as_none() {
    assert_eq!(parse_optional_bind(Some("   ")).unwrap(), None);
    assert_eq!(
        parse_optional_bind(Some("127.0.0.1:3022")).unwrap(),
        Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3022))
    );
}

#[test]
fn listener_addresses_conflict_handles_unspecified_host() {
    let public = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 3022);
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3022);
    let other = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4022);

    assert!(listener_addresses_conflict(public, local));
    assert!(!listener_addresses_conflict(public, other));
}

#[test]
fn healthcheck_target_rewrites_unspecified_host_to_loopback() {
    let target = healthcheck_target("0.0.0.0:3022").unwrap();
    assert_eq!(
        target,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3022)
    );
}

#[test]
fn healthcheck_url_prefers_local_bind_for_http() {
    let config = ServerConfig {
        bind: "0.0.0.0:3022".to_string(),
        local_bind: Some("127.0.0.1:4022".to_string()),
        ..ServerConfig::default()
    };

    assert_eq!(
        healthcheck_url(&config).unwrap(),
        "http://127.0.0.1:4022/api/v1/health"
    );
}

#[test]
fn healthcheck_url_uses_https_for_explicit_tls_host() {
    let config = ServerConfig {
        bind: "192.0.2.10:3022".to_string(),
        tls_cert_path: Some("/etc/bannkenn/tls/server.crt".to_string()),
        tls_key_path: Some("/etc/bannkenn/tls/server.key".to_string()),
        ..ServerConfig::default()
    };

    assert_eq!(
        healthcheck_url(&config).unwrap(),
        "https://192.0.2.10:3022/api/v1/health"
    );
}

#[test]
fn healthcheck_url_rejects_tls_with_unspecified_host() {
    let config = ServerConfig {
        bind: "0.0.0.0:3022".to_string(),
        tls_cert_path: Some("/etc/bannkenn/tls/server.crt".to_string()),
        tls_key_path: Some("/etc/bannkenn/tls/server.key".to_string()),
        ..ServerConfig::default()
    };

    assert!(healthcheck_url(&config).is_err());
}
