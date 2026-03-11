use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use reqwest::Url;
use rustls::client::{ServerCertVerified, ServerCertVerifier, ServerName};
use rustls::{Certificate, ClientConfig, Error as RustlsError};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedCertificate {
    pub der: Vec<u8>,
    pub sha256_fingerprint: String,
}

#[derive(Debug)]
struct CaptureVerifier {
    presented_der: Arc<Mutex<Option<Vec<u8>>>>,
}

impl CaptureVerifier {
    fn new(presented_der: Arc<Mutex<Option<Vec<u8>>>>) -> Self {
        Self { presented_der }
    }
}

impl ServerCertVerifier for CaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        *self
            .presented_der
            .lock()
            .expect("poisoned cert capture mutex") = Some(end_entity.0.clone());
        Ok(ServerCertVerified::assertion())
    }
}

pub async fn fetch_presented_certificate(server_url: &str) -> Result<PresentedCertificate> {
    let url = Url::parse(server_url).context("invalid server_url")?;
    if url.scheme() != "https" {
        return Err(anyhow!("trust-on-first-use only applies to https URLs"));
    }

    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("server_url is missing a hostname"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("server_url is missing a port and has no known default"))?;
    let server_name =
        ServerName::try_from(host).map_err(|_| anyhow!("invalid TLS server name '{}'", host))?;

    let presented_der = Arc::new(Mutex::new(None));
    let verifier = Arc::new(CaptureVerifier::new(Arc::clone(&presented_der)));
    let client_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));

    let tcp = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("failed to connect to {}:{}", host, port))?;
    connector
        .connect(server_name, tcp)
        .await
        .with_context(|| format!("TLS handshake failed for {}", server_url))?;

    let der = presented_der
        .lock()
        .expect("poisoned cert capture mutex")
        .clone()
        .ok_or_else(|| anyhow!("server did not present a certificate"))?;

    Ok(PresentedCertificate {
        sha256_fingerprint: sha256_fingerprint(&der),
        der,
    })
}

pub fn save_presented_certificate(
    server_url: &str,
    cert: &PresentedCertificate,
) -> Result<PathBuf> {
    let path = pinned_cert_path(server_url)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(&path, pem_encode_certificate(&cert.der))
        .with_context(|| format!("failed to write pinned certificate to {}", path.display()))?;
    Ok(path)
}

fn pinned_cert_path(server_url: &str) -> Result<PathBuf> {
    let url = Url::parse(server_url).context("invalid server_url")?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("server_url is missing a hostname"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("server_url is missing a port and has no known default"))?;
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
    Ok(home
        .join(".config/bannkenn/certs")
        .join(format!("{}.pem", sanitize_host_port(host, port))))
}

fn sanitize_host_port(host: &str, port: u16) -> String {
    let sanitized_host: String = host
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    format!("{}_{}", sanitized_host, port)
}

fn pem_encode_certificate(der: &[u8]) -> String {
    let base64 = STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in base64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 chunk must be utf8"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

fn sha256_fingerprint(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    digest
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_host_port_replaces_non_alnum() {
        assert_eq!(
            sanitize_host_port("221.103.201.166", 1234),
            "221_103_201_166_1234"
        );
        assert_eq!(sanitize_host_port("2001:db8::1", 443), "2001_db8__1_443");
    }

    #[test]
    fn pem_encoder_wraps_certificate_body() {
        let pem = pem_encode_certificate(&[1, 2, 3, 4]);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
    }

    #[test]
    fn fingerprint_is_uppercase_colon_hex() {
        let fingerprint = sha256_fingerprint(b"bannkenn");
        assert!(fingerprint.contains(':'));
        assert_eq!(fingerprint, fingerprint.to_ascii_uppercase());
    }
}
