use crate::shared_risk::SharedRiskSnapshot;
use anyhow::Result;
use reqwest::{Certificate, Client as HttpClient};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;

/// Mirror of the server's DecisionRow for deserialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRow {
    pub id: i64,
    pub ip: String,
    pub reason: String,
    pub action: String,
    pub source: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistEntry {
    pub id: i64,
    pub ip: String,
    pub note: Option<String>,
    pub created_at: String,
}

/// API client for communicating with the BannKenn server
#[derive(Clone)]
pub struct ApiClient {
    base_url: String,
    token: String,
    http: HttpClient,
}

impl ApiClient {
    /// Create a new API client
    pub fn new(base_url: String, token: String, ca_cert_path: Option<String>) -> Result<Self> {
        Ok(Self {
            base_url,
            token,
            http: build_http_client(ca_cert_path.as_deref())?,
        })
    }

    /// Fetch decisions with id > since_id in ascending order (for sync)
    pub async fn fetch_decisions_since(&self, since_id: i64) -> Result<Vec<DecisionRow>> {
        let url = format!("{}/api/v1/decisions?since_id={}", self.base_url, since_id);

        let response = self.http.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Server returned error {} fetching decisions: {}",
                status,
                text
            ));
        }

        let rows: Vec<DecisionRow> = response.json().await?;
        Ok(rows)
    }

    /// Fetch centrally managed IP whitelist entries.
    pub async fn fetch_whitelist(&self) -> Result<Vec<WhitelistEntry>> {
        let url = format!("{}/api/v1/whitelist", self.base_url);

        let response = self.http.get(&url).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Server returned whitelist error {}: {}",
                status,
                text
            ));
        }

        let rows: Vec<WhitelistEntry> = response.json().await?;
        Ok(rows)
    }

    /// Fetch the server-computed shared risk profile for all agents.
    pub async fn fetch_shared_risk_profile(&self) -> Result<SharedRiskSnapshot> {
        let url = format!("{}/api/v1/agents/shared-risk", self.base_url);

        let response = self
            .http
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Server returned shared-risk error {}: {}",
                status,
                text
            ));
        }

        Ok(response.json().await?)
    }

    /// Report a block decision to the server
    pub async fn report_decision(&self, ip: &str, reason: &str) -> Result<()> {
        let url = format!("{}/api/v1/decisions", self.base_url);

        let body = json!({
            "ip": ip,
            "reason": reason,
            "action": "block"
        });

        let response = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Server returned error {}: {}",
                status,
                text
            ));
        }

        tracing::debug!("Successfully reported decision for IP {}", ip);
        Ok(())
    }

    /// Report a telemetry event (alert/block) to the server.
    pub async fn report_telemetry(
        &self,
        ip: &str,
        reason: &str,
        level: &str,
        log_path: Option<&str>,
    ) -> Result<()> {
        let url = format!("{}/api/v1/telemetry", self.base_url);

        let body = json!({
            "ip": ip,
            "reason": reason,
            "level": level,
            "log_path": log_path
        });

        let response = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Server returned telemetry error {}: {}",
                status,
                text
            ));
        }

        Ok(())
    }

    /// Report a successful SSH login event to the server.
    pub async fn report_ssh_login(&self, ip: &str, username: &str) -> Result<()> {
        let url = format!("{}/api/v1/ssh-logins", self.base_url);

        let body = json!({
            "ip": ip,
            "username": username
        });

        let response = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Server returned ssh-login error {}: {}",
                status,
                text
            ));
        }

        tracing::debug!("SSH login reported: user={} ip={}", username, ip);
        Ok(())
    }

    /// Send heartbeat so server can mark this agent as online.
    /// Optionally reports ButterflyShield status.
    pub async fn send_heartbeat(&self, butterfly_shield_enabled: Option<bool>) -> Result<()> {
        let url = format!("{}/api/v1/agents/heartbeat", self.base_url);

        let body = json!({ "butterfly_shield_enabled": butterfly_shield_enabled });

        let response = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "Server returned heartbeat error {}: {}",
                status,
                text
            ));
        }

        tracing::debug!("Heartbeat sent successfully");
        Ok(())
    }
}

pub fn build_http_client(ca_cert_path: Option<&str>) -> Result<HttpClient> {
    let mut builder = HttpClient::builder();

    if let Some(path) = ca_cert_path.filter(|value| !value.trim().is_empty()) {
        let pem = fs::read(path)?;
        let cert = Certificate::from_pem(&pem)?;
        builder = builder.add_root_certificate(cert);
    }

    Ok(builder.build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = ApiClient::new(
            "http://localhost:8080".to_string(),
            "test_token".to_string(),
            None,
        )
        .unwrap();

        assert_eq!(client.base_url, "http://localhost:8080");
        assert_eq!(client.token, "test_token");
    }

    #[test]
    fn test_http_client_creation_without_custom_ca() {
        let client = build_http_client(None).unwrap();
        let clone = client.clone();
        drop(clone);
    }

    #[test]
    fn test_json_body_construction() {
        let body = json!({
            "ip": "192.168.1.1",
            "reason": "Failed login attempts",
            "action": "block"
        });

        assert_eq!(body["ip"], "192.168.1.1");
        assert_eq!(body["action"], "block");
    }
}
