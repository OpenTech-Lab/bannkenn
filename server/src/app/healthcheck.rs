use super::runtime::parse_optional_bind;
use crate::config::ServerConfig;
use anyhow::{bail, Context};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub async fn run_healthcheck() -> anyhow::Result<()> {
    let config = ServerConfig::load()?;
    let url = healthcheck_url(&config)?;

    let client = if url.starts_with("https://") {
        let tls_config = config
            .tls_config()?
            .context("HTTPS healthcheck requires tls_cert_path and tls_key_path")?;
        reqwest::Client::builder()
            .add_root_certificate(load_reqwest_certificate(&tls_config.cert_path)?)
            .build()
            .context("failed to build HTTPS healthcheck client")?
    } else {
        reqwest::Client::builder()
            .build()
            .context("failed to build healthcheck client")?
    };

    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("failed to connect to {}", url))?;

    if !response.status().is_success() {
        bail!("unexpected healthcheck status {}", response.status());
    }

    let body: serde_json::Value = response
        .json()
        .await
        .context("failed to decode healthcheck JSON response")?;

    if body.get("status").and_then(|status| status.as_str()) == Some("ok") {
        return Ok(());
    }

    bail!("unexpected healthcheck response")
}

pub fn healthcheck_url(config: &ServerConfig) -> anyhow::Result<String> {
    if let Some(local_addr) = parse_optional_bind(config.local_bind.as_deref())? {
        let target = healthcheck_target(&local_addr.to_string())?;
        return Ok(format!("http://{}/api/v1/health", target));
    }

    if config.tls_config()?.is_some() {
        let addr: SocketAddr = config.bind.parse()?;
        if addr.ip().is_unspecified() {
            bail!(
                "HTTPS healthcheck requires BANNKENN_LOCAL_BIND or an explicit BANNKENN_BIND host that matches the certificate SAN"
            );
        }
        return Ok(format!("https://{}/api/v1/health", addr));
    }

    let target = healthcheck_target(&config.bind)?;
    Ok(format!("http://{}/api/v1/health", target))
}

pub fn healthcheck_target(bind: &str) -> anyhow::Result<SocketAddr> {
    let addr: SocketAddr = bind.parse()?;
    let ip = match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };

    Ok(SocketAddr::new(ip, addr.port()))
}

fn load_reqwest_certificate(path: &str) -> anyhow::Result<reqwest::Certificate> {
    let bytes = std::fs::read(path).with_context(|| format!("failed to read TLS cert {}", path))?;
    reqwest::Certificate::from_pem(&bytes).context("failed to parse PEM certificate")
}
