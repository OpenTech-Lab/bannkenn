use crate::config::AgentConfig;
use anyhow::Result;
use chrono::{DateTime, Utc};
use regex::Regex;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

/// Event indicating an IP should be blocked
#[derive(Debug, Clone)]
pub struct BlockEvent {
    pub ip: String,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

/// Monitors log file for failed SSH login attempts and sends block events
/// when threshold is exceeded within a time window
pub async fn watch(config: Arc<AgentConfig>, tx: mpsc::Sender<BlockEvent>) -> Result<()> {
    // Compile regex patterns for failed login detection
    let failed_password_re = Regex::new(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")?;
    let invalid_user_re = Regex::new(r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)")?;

    // Sliding window counters: IP -> Vec of timestamps
    let mut ip_attempts: HashMap<String, VecDeque<Instant>> = HashMap::new();

    // Open the log file
    let mut file = File::open(&config.log_path).await?;

    // Seek to end of file to start tailing from new entries
    file.seek(std::io::SeekFrom::End(0)).await?;

    let mut buffer = String::new();
    let poll_interval = Duration::from_millis(200);

    loop {
        // Read new lines from the file
        buffer.clear();
        match file.read_to_string(&mut buffer).await {
            Ok(0) => {
                // EOF reached, sleep and retry
                sleep(poll_interval).await;
                continue;
            }
            Ok(_) => {
                // Process new lines
                for line in buffer.lines() {
                    // Try to extract IP from failed password regex
                    if let Some(caps) = failed_password_re.captures(line) {
                        if let Some(ip_match) = caps.get(1) {
                            let ip = ip_match.as_str().to_string();
                            process_failed_attempt(
                                &ip,
                                &mut ip_attempts,
                                &config,
                                &tx,
                                "Failed SSH password attempt",
                            )
                            .await;
                        }
                    }

                    // Try to extract IP from invalid user regex
                    if let Some(caps) = invalid_user_re.captures(line) {
                        if let Some(ip_match) = caps.get(1) {
                            let ip = ip_match.as_str().to_string();
                            process_failed_attempt(
                                &ip,
                                &mut ip_attempts,
                                &config,
                                &tx,
                                "Invalid SSH user attempt",
                            )
                            .await;
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Error reading log file: {}", e);
                sleep(poll_interval).await;
            }
        }
    }
}

/// Process a failed login attempt and send block event if threshold exceeded
async fn process_failed_attempt(
    ip: &str,
    ip_attempts: &mut HashMap<String, VecDeque<Instant>>,
    config: &AgentConfig,
    tx: &mpsc::Sender<BlockEvent>,
    reason: &str,
) {
    let now = Instant::now();
    let window = Duration::from_secs(config.window_secs);

    // Get or create entry for this IP
    let attempts = ip_attempts.entry(ip.to_string()).or_insert_with(VecDeque::new);

    // Remove old attempts outside the window
    while let Some(&oldest) = attempts.front() {
        if now.duration_since(oldest) > window {
            attempts.pop_front();
        } else {
            break;
        }
    }

    // Add current attempt
    attempts.push_back(now);

    // Check if threshold exceeded
    if attempts.len() >= config.threshold as usize {
        let block_event = BlockEvent {
            ip: ip.to_string(),
            reason: format!("{} (threshold: {})", reason, config.threshold),
            timestamp: Utc::now(),
        };

        tracing::info!("Threshold exceeded for IP {}: {} attempts", ip, attempts.len());

        // Send block event (ignore send errors if receiver dropped)
        let _ = tx.send(block_event).await;

        // Clear attempts for this IP to avoid duplicate blocks
        attempts.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failed_password_regex() {
        let re = Regex::new(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)").unwrap();
        let line = "Jan 15 10:23:45 server sshd[1234]: Failed password for user from 192.168.1.100 port 22 ssh2";
        let caps = re.captures(line).unwrap();
        assert_eq!(caps.get(1).unwrap().as_str(), "192.168.1.100");
    }

    #[test]
    fn test_invalid_user_regex() {
        let re = Regex::new(r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)").unwrap();
        let line = "Jan 15 10:25:12 server sshd[5678]: Invalid user admin from 10.0.0.50 port 22";
        let caps = re.captures(line).unwrap();
        assert_eq!(caps.get(1).unwrap().as_str(), "10.0.0.50");
    }

    #[test]
    fn test_multiple_ips_in_log() {
        let re = Regex::new(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)").unwrap();
        let line1 = "Failed password for user from 192.168.1.1";
        let line2 = "Failed password for admin from 10.0.0.1";

        let ip1 = re.captures(line1).unwrap().get(1).unwrap().as_str();
        let ip2 = re.captures(line2).unwrap().get(1).unwrap().as_str();

        assert_eq!(ip1, "192.168.1.1");
        assert_eq!(ip2, "10.0.0.1");
    }
}
