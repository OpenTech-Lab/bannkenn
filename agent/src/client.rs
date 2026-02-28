use anyhow::Result;
use reqwest::Client as HttpClient;
use serde_json::json;

/// API client for communicating with the BannKenn server
pub struct ApiClient {
    base_url: String,
    token: String,
    http: HttpClient,
}

impl ApiClient {
    /// Create a new API client
    pub fn new(base_url: String, token: String) -> Self {
        Self {
            base_url,
            token,
            http: HttpClient::new(),
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = ApiClient::new(
            "http://localhost:8080".to_string(),
            "test_token".to_string(),
        );

        assert_eq!(client.base_url, "http://localhost:8080");
        assert_eq!(client.token, "test_token");
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
