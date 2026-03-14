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
        report: BehaviorEventUpload,
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
            report: BehaviorEventUpload::from(event),
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
mod tests {
    use super::*;
    use crate::reporting::{
        BehaviorEventUpload, ContainmentOutcomeUpload, ContainmentStatusUpload,
    };

    #[test]
    fn outbox_round_trips_and_acks_items() {
        let dir = std::env::temp_dir().join(format!("bannkenn-outbox-{}", uuid::Uuid::new_v4()));
        let path = dir.join("outbox.toml");

        let mut outbox = Outbox::load(path.clone());
        assert_eq!(outbox.len(), 0);

        let first_id = outbox
            .enqueue(OutboxPayload::Telemetry {
                ip: "203.0.113.10".to_string(),
                reason: "Invalid SSH user".to_string(),
                level: "alert".to_string(),
                log_path: Some("/var/log/auth.log".to_string()),
                timestamp: Some("2026-03-11T09:00:00+00:00".to_string()),
            })
            .unwrap();
        let second_id = outbox
            .enqueue(OutboxPayload::Decision {
                ip: "203.0.113.10".to_string(),
                reason: "Invalid SSH user [High] (threshold: 1)".to_string(),
                timestamp: Some("2026-03-11T09:00:01+00:00".to_string()),
            })
            .unwrap();

        assert_eq!(first_id, 1);
        assert_eq!(second_id, 2);

        let reloaded = Outbox::load(path);
        assert_eq!(reloaded.len(), 2);
        assert_eq!(reloaded.peek().unwrap().id, first_id);

        let mut reloaded = reloaded;
        assert!(reloaded.ack(first_id).unwrap());
        assert_eq!(reloaded.len(), 1);
        assert_eq!(reloaded.peek().unwrap().id, second_id);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn outbox_loads_legacy_items_without_timestamps() {
        let dir = std::env::temp_dir().join(format!("bannkenn-outbox-{}", uuid::Uuid::new_v4()));
        let path = dir.join("outbox.toml");

        fs::create_dir_all(&dir).unwrap();
        fs::write(
            &path,
            r#"
next_id = 3

[[items]]
id = 1
kind = "decision"
ip = "203.0.113.10"
reason = "Invalid SSH user"

[[items]]
id = 2
kind = "ssh_login"
ip = "203.0.113.20"
username = "root"
"#,
        )
        .unwrap();

        let outbox = Outbox::load(path);
        assert_eq!(outbox.len(), 2);

        match outbox.peek().unwrap().payload {
            OutboxPayload::Decision { timestamp, .. } => assert_eq!(timestamp, None),
            payload => panic!("expected decision payload, got {payload:?}"),
        }

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn outbox_round_trips_behavior_and_containment_reports() {
        let dir = std::env::temp_dir().join(format!("bannkenn-outbox-{}", uuid::Uuid::new_v4()));
        let path = dir.join("outbox.toml");

        let mut outbox = Outbox::load(path.clone());
        outbox
            .enqueue(OutboxPayload::BehaviorEvent {
                report: BehaviorEventUpload {
                    timestamp: "2026-03-14T10:00:00+00:00".to_string(),
                    source: "ebpf_ringbuf".to_string(),
                    watched_root: "/srv/data".to_string(),
                    pid: Some(42),
                    process_name: Some("python3".to_string()),
                    exe_path: Some("/usr/bin/python3".to_string()),
                    command_line: Some("python3 encrypt.py".to_string()),
                    correlation_hits: 3,
                    file_ops: crate::ebpf::events::FileOperationCounts {
                        modified: 5,
                        renamed: 2,
                        ..Default::default()
                    },
                    touched_paths: vec!["/srv/data/a.txt".to_string()],
                    protected_paths_touched: vec!["/srv/data/secret.txt".to_string()],
                    bytes_written: 4096,
                    io_rate_bytes_per_sec: 2048,
                    score: 61,
                    reasons: vec!["rename burst".to_string()],
                    level: "throttle_candidate".to_string(),
                },
            })
            .unwrap();
        outbox
            .enqueue(OutboxPayload::ContainmentStatus {
                report: ContainmentStatusUpload {
                    timestamp: "2026-03-14T10:00:05+00:00".to_string(),
                    state: "throttle".to_string(),
                    previous_state: Some("suspicious".to_string()),
                    reason: "throttle score threshold crossed".to_string(),
                    watched_root: "/srv/data".to_string(),
                    pid: Some(42),
                    score: 61,
                    actions: vec!["ApplyIoThrottle".to_string()],
                    outcomes: vec![ContainmentOutcomeUpload {
                        enforcer: "cgroup".to_string(),
                        applied: false,
                        dry_run: true,
                        detail: "dry-run".to_string(),
                    }],
                },
            })
            .unwrap();

        let reloaded = Outbox::load(path);
        assert_eq!(reloaded.len(), 2);

        match reloaded.peek().unwrap().payload {
            OutboxPayload::BehaviorEvent { report } => {
                assert_eq!(report.source, "ebpf_ringbuf");
                assert_eq!(report.level, "throttle_candidate");
            }
            payload => panic!("expected behavior event payload, got {payload:?}"),
        }

        let _ = fs::remove_dir_all(dir);
    }
}
