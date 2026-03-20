use crate::client::ApiClient;
use crate::containment::ContainmentDecision;
use crate::ebpf::events::BehaviorEvent;
use crate::reporting::{BehaviorEventUpload, ContainmentStatusUpload};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OutboxPayload {
    Decision {
        ip: String,
        reason: String,
        #[serde(default)]
        timestamp: Option<String>,
    },
    Telemetry {
        ip: String,
        reason: String,
        level: String,
        log_path: Option<String>,
        #[serde(default)]
        timestamp: Option<String>,
    },
    SshLogin {
        ip: String,
        username: String,
        #[serde(default)]
        timestamp: Option<String>,
    },
    BehaviorEvent {
        report: Box<BehaviorEventUpload>,
    },
    ContainmentStatus {
        report: ContainmentStatusUpload,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutboxItem {
    pub id: u64,
    #[serde(flatten)]
    pub payload: OutboxPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
struct OutboxState {
    #[serde(default = "default_next_id")]
    next_id: u64,
    #[serde(default)]
    items: Vec<OutboxItem>,
}

fn default_next_id() -> u64 {
    1
}

#[derive(Debug)]
pub struct Outbox {
    path: PathBuf,
    state: OutboxState,
}

impl Outbox {
    pub fn load_default() -> Result<Self> {
        let path = Self::state_path()?;
        Ok(Self::load(path))
    }

    pub fn load(path: PathBuf) -> Self {
        let state = fs::read_to_string(&path)
            .ok()
            .and_then(|content| toml::from_str(&content).ok())
            .unwrap_or_default();
        Self { path, state }
    }

    pub fn len(&self) -> usize {
        self.state.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.state.items.is_empty()
    }

    pub fn enqueue(&mut self, payload: OutboxPayload) -> Result<u64> {
        let id = self.state.next_id.max(1);
        self.state.next_id = id + 1;
        self.state.items.push(OutboxItem { id, payload });
        self.save()?;
        Ok(id)
    }

    pub fn peek(&self) -> Option<OutboxItem> {
        self.state.items.first().cloned()
    }

    pub fn ack(&mut self, id: u64) -> Result<bool> {
        let before = self.state.items.len();
        self.state.items.retain(|item| item.id != id);
        let removed = self.state.items.len() != before;
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    fn save(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let toml_string = toml::to_string_pretty(&self.state)?;
        fs::write(&self.path, toml_string)?;
        Ok(())
    }

    fn state_path() -> Result<PathBuf> {
        let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
        Ok(home.join(".config/bannkenn/outbox.toml"))
    }
}

impl OutboxPayload {
    pub fn from_behavior_event(event: &BehaviorEvent) -> Self {
        Self::BehaviorEvent {
            report: Box::new(BehaviorEventUpload::from(event)),
        }
    }

    pub fn from_containment_decision(decision: &ContainmentDecision) -> Option<Self> {
        ContainmentStatusUpload::from_decision(decision)
            .map(|report| Self::ContainmentStatus { report })
    }
}

pub async fn flush_pending(
    client: &ApiClient,
    outbox: &Arc<Mutex<Outbox>>,
    max_items: usize,
) -> Result<usize> {
    let mut sent = 0usize;

    for _ in 0..max_items {
        let next = { outbox.lock().await.peek() };
        let Some(item) = next else {
            break;
        };

        let send_result = match &item.payload {
            OutboxPayload::Decision {
                ip,
                reason,
                timestamp,
            } => {
                client
                    .report_decision(ip, reason, timestamp.as_deref())
                    .await
            }
            OutboxPayload::Telemetry {
                ip,
                reason,
                level,
                log_path,
                timestamp,
            } => {
                client
                    .report_telemetry(ip, reason, level, log_path.as_deref(), timestamp.as_deref())
                    .await
            }
            OutboxPayload::SshLogin {
                ip,
                username,
                timestamp,
            } => {
                client
                    .report_ssh_login(ip, username, timestamp.as_deref())
                    .await
            }
            OutboxPayload::BehaviorEvent { report } => client.report_behavior_event(report).await,
            OutboxPayload::ContainmentStatus { report } => {
                client.report_containment_status(report).await
            }
        };

        match send_result {
            Ok(_) => {
                let removed = outbox.lock().await.ack(item.id)?;
                if removed {
                    sent += 1;
                }
            }
            Err(err) => {
                tracing::warn!("outbox flush stopped on item {}: {}", item.id, err);
                break;
            }
        }
    }

    Ok(sent)
}

#[cfg(test)]
#[path = "../tests/unit/outbox_tests.rs"]
mod tests;
