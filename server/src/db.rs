use crate::geoip;
use crate::ip_pattern::{canonicalize_ip_pattern, pattern_covers_pattern};
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool};
use sqlx::Row;
use std::str::FromStr;
use std::time::Duration;

fn normalize_reason_category(reason: &str) -> &str {
    if let Some(idx) = reason.rfind(" (") {
        let suffix = &reason[idx + 2..];
        if suffix.ends_with(')') {
            return &reason[..idx];
        }
    }
    reason
}

fn telemetry_level_weight(level: &str) -> f64 {
    match level {
        "block" => 3.0,
        "listed" => 2.0,
        _ => 1.0,
    }
}

fn normalize_event_timestamp(timestamp: Option<&str>) -> String {
    match timestamp {
        Some(value) => match DateTime::parse_from_rfc3339(value) {
            Ok(parsed) => parsed.with_timezone(&Utc).to_rfc3339(),
            Err(err) => {
                tracing::warn!(
                    "invalid event timestamp '{}', falling back to receipt time: {}",
                    value,
                    err
                );
                Utc::now().to_rfc3339()
            }
        },
        None => Utc::now().to_rfc3339(),
    }
}

fn normalize_lookup_geo(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown") {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn encode_json<T: Serialize>(value: &T) -> anyhow::Result<String> {
    Ok(serde_json::to_string(value)?)
}

fn decode_json<T: DeserializeOwned>(value: &str, field: &str) -> anyhow::Result<T> {
    serde_json::from_str(value)
        .map_err(|err| anyhow::anyhow!("failed to decode {} JSON: {}", field, err))
}

fn to_i64<T>(value: T, field: &str) -> anyhow::Result<i64>
where
    T: TryInto<i64>,
    T::Error: std::fmt::Display,
{
    value
        .try_into()
        .map_err(|err| anyhow::anyhow!("{} out of range: {}", field, err))
}

fn from_i64_u32(value: i64, field: &str) -> anyhow::Result<u32> {
    u32::try_from(value).map_err(|_| anyhow::anyhow!("{} out of range: {}", field, value))
}

fn from_i64_u64(value: i64, field: &str) -> anyhow::Result<u64> {
    u64::try_from(value).map_err(|_| anyhow::anyhow!("{} out of range: {}", field, value))
}

fn from_i64_opt_u32(value: Option<i64>, field: &str) -> anyhow::Result<Option<u32>> {
    value.map(|value| from_i64_u32(value, field)).transpose()
}

fn source_label(source: &str, agent_display_name: Option<String>) -> String {
    agent_display_name
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| match source {
            "campaign" => "Campaign auto-block".to_string(),
            _ => source.to_string(),
        })
}

fn source_kind(source: &str, agent_id: Option<i64>) -> &'static str {
    if agent_id.is_some() {
        "agent"
    } else if source == "campaign" {
        "campaign"
    } else {
        "community"
    }
}

#[derive(Debug, Clone)]
pub struct Db(SqlitePool);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRow {
    pub id: i64,
    pub ip: String,
    pub reason: String,
    pub action: String,
    pub source: String,
    pub country: Option<String>,
    pub asn_org: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryRow {
    pub id: i64,
    pub ip: String,
    pub reason: String,
    pub level: String,
    pub source: String,
    pub log_path: Option<String>,
    pub country: Option<String>,
    pub asn_org: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BehaviorFileOpsRow {
    pub created: u32,
    pub modified: u32,
    pub renamed: u32,
    pub deleted: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BehaviorEventRow {
    pub id: i64,
    pub agent_name: String,
    pub source: String,
    pub watched_root: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub exe_path: Option<String>,
    pub command_line: Option<String>,
    pub correlation_hits: u32,
    pub file_ops: BehaviorFileOpsRow,
    pub touched_paths: Vec<String>,
    pub protected_paths_touched: Vec<String>,
    pub bytes_written: u64,
    pub io_rate_bytes_per_sec: u64,
    pub score: u32,
    pub reasons: Vec<String>,
    pub level: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainmentOutcomeRow {
    pub enforcer: String,
    pub applied: bool,
    pub dry_run: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainmentEventRow {
    pub id: i64,
    pub agent_name: String,
    pub state: String,
    pub previous_state: Option<String>,
    pub reason: String,
    pub watched_root: String,
    pub pid: Option<u32>,
    pub score: u32,
    pub actions: Vec<String>,
    pub outcomes: Vec<ContainmentOutcomeRow>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainmentStatusRow {
    pub agent_name: String,
    pub state: String,
    pub previous_state: Option<String>,
    pub reason: String,
    pub watched_root: String,
    pub pid: Option<u32>,
    pub score: u32,
    pub actions: Vec<String>,
    pub outcomes: Vec<ContainmentOutcomeRow>,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct NewBehaviorEvent {
    pub agent_name: String,
    pub source: String,
    pub watched_root: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub exe_path: Option<String>,
    pub command_line: Option<String>,
    pub correlation_hits: u32,
    pub file_ops: BehaviorFileOpsRow,
    pub touched_paths: Vec<String>,
    pub protected_paths_touched: Vec<String>,
    pub bytes_written: u64,
    pub io_rate_bytes_per_sec: u64,
    pub score: u32,
    pub reasons: Vec<String>,
    pub level: String,
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewContainmentEvent {
    pub agent_name: String,
    pub state: String,
    pub previous_state: Option<String>,
    pub reason: String,
    pub watched_root: String,
    pub pid: Option<u32>,
    pub score: u32,
    pub actions: Vec<String>,
    pub outcomes: Vec<ContainmentOutcomeRow>,
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRow {
    pub id: i64,
    pub name: String,
    pub token_hash: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatusRow {
    pub id: i64,
    pub name: String,
    pub uuid: Option<String>,
    pub nickname: Option<String>,
    pub created_at: String,
    pub last_seen_at: Option<String>,
    pub butterfly_shield_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshLoginRow {
    pub id: i64,
    pub ip: String,
    pub username: String,
    pub agent_name: String,
    pub country: Option<String>,
    pub asn_org: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityIpRow {
    pub ip: String,
    pub source: String,
    pub source_label: String,
    pub kind: String,
    pub sightings: i64,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityFeedRow {
    pub source: String,
    pub source_label: String,
    pub kind: String,
    pub ip_count: i64,
    pub first_seen_at: String,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityFeedIpRow {
    pub ip: String,
    pub reason: String,
    pub sightings: i64,
    pub first_seen_at: String,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpLookupEventRow {
    pub id: i64,
    pub source: String,
    pub source_label: String,
    pub agent_id: Option<i64>,
    pub reason: String,
    pub level: String,
    pub log_path: Option<String>,
    pub country: Option<String>,
    pub asn_org: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpLookupDecisionRow {
    pub id: i64,
    pub source: String,
    pub source_label: String,
    pub agent_id: Option<i64>,
    pub reason: String,
    pub action: String,
    pub country: Option<String>,
    pub asn_org: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpLookupMachineSummaryRow {
    pub agent_id: Option<i64>,
    pub source: String,
    pub source_label: String,
    pub event_count: i64,
    pub alert_count: i64,
    pub listed_count: i64,
    pub block_count: i64,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub last_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpLookupCommunityMatchRow {
    pub source: String,
    pub matched_entry: String,
    pub reason: String,
    pub sightings: i64,
    pub first_seen_at: String,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpLookupResponse {
    pub ip: String,
    pub country: Option<String>,
    pub asn_org: Option<String>,
    pub local_history: Vec<IpLookupEventRow>,
    pub decision_history: Vec<IpLookupDecisionRow>,
    pub machine_summaries: Vec<IpLookupMachineSummaryRow>,
    pub community_matches: Vec<IpLookupCommunityMatchRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SharedRiskCategoryRow {
    pub category: String,
    pub distinct_ips: u32,
    pub distinct_agents: u32,
    pub event_count: u32,
    pub threshold_multiplier: f64,
    pub force_threshold: Option<u32>,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WhitelistEntryRow {
    pub id: i64,
    pub ip: String,
    pub note: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SharedRiskProfileRow {
    pub generated_at: String,
    pub window_secs: i64,
    pub global_risk_score: f64,
    pub global_threshold_multiplier: f64,
    pub categories: Vec<SharedRiskCategoryRow>,
}

impl Db {
    pub async fn new(path: &str) -> anyhow::Result<Self> {
        let opts = SqliteConnectOptions::from_str(&format!("sqlite:{}", path))?
            .create_if_missing(true)
            .busy_timeout(Duration::from_secs(30))
            .journal_mode(SqliteJournalMode::Wal);
        let pool = SqlitePool::connect_with(opts).await?;
        let db = Db(pool);
        db.migrate().await?;
        Ok(db)
    }

    pub async fn migrate(&self) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                reason TEXT NOT NULL,
                action TEXT NOT NULL DEFAULT 'block',
                source TEXT NOT NULL DEFAULT 'agent',
                country TEXT,
                asn_org TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT
            )
            "#,
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS telemetry_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                reason TEXT NOT NULL,
                level TEXT NOT NULL,
                source TEXT NOT NULL,
                log_path TEXT,
                country TEXT,
                asn_org TEXT,
                created_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS behavior_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_name TEXT NOT NULL,
                source TEXT NOT NULL,
                watched_root TEXT NOT NULL,
                pid INTEGER,
                process_name TEXT,
                exe_path TEXT,
                command_line TEXT,
                correlation_hits INTEGER NOT NULL DEFAULT 0,
                file_ops_created INTEGER NOT NULL DEFAULT 0,
                file_ops_modified INTEGER NOT NULL DEFAULT 0,
                file_ops_renamed INTEGER NOT NULL DEFAULT 0,
                file_ops_deleted INTEGER NOT NULL DEFAULT 0,
                touched_paths_json TEXT NOT NULL DEFAULT '[]',
                protected_paths_json TEXT NOT NULL DEFAULT '[]',
                bytes_written INTEGER NOT NULL DEFAULT 0,
                io_rate_bytes_per_sec INTEGER NOT NULL DEFAULT 0,
                score INTEGER NOT NULL DEFAULT 0,
                reasons_json TEXT NOT NULL DEFAULT '[]',
                level TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS containment_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_name TEXT NOT NULL,
                state TEXT NOT NULL,
                previous_state TEXT,
                reason TEXT NOT NULL,
                watched_root TEXT NOT NULL,
                pid INTEGER,
                score INTEGER NOT NULL DEFAULT 0,
                actions_json TEXT NOT NULL DEFAULT '[]',
                outcomes_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS agent_containment_status (
                agent_name TEXT PRIMARY KEY,
                state TEXT NOT NULL,
                previous_state TEXT,
                reason TEXT NOT NULL,
                watched_root TEXT NOT NULL,
                pid INTEGER,
                score INTEGER NOT NULL DEFAULT 0,
                actions_json TEXT NOT NULL DEFAULT '[]',
                outcomes_json TEXT NOT NULL DEFAULT '[]',
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                token_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_decisions_ip ON decisions(ip)
            "#,
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_decisions_created_at ON decisions(created_at DESC)
            "#,
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_decisions_source_created_at ON decisions(source, created_at DESC)
            "#,
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_telemetry_source_created_at ON telemetry_events(source, created_at DESC)
            "#,
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_telemetry_created_at ON telemetry_events(created_at DESC)
            "#,
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_telemetry_ip_source_created_at ON telemetry_events(ip, source, created_at DESC)
            "#,
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_behavior_events_created_at ON behavior_events(created_at DESC)
            "#,
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_behavior_events_agent_created_at ON behavior_events(agent_name, created_at DESC)
            "#,
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_behavior_events_level_created_at ON behavior_events(level, created_at DESC)
            "#,
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_containment_events_created_at ON containment_events(created_at DESC)
            "#,
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_containment_events_agent_created_at ON containment_events(agent_name, created_at DESC)
            "#,
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_agent_containment_status_updated_at ON agent_containment_status(updated_at DESC)
            "#,
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS agent_heartbeats (
                agent_name TEXT PRIMARY KEY,
                last_heartbeat_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.0)
        .await?;

        // Add uuid and nickname columns if they don't exist (idempotent for existing DBs)
        let _ = sqlx::query("ALTER TABLE agents ADD COLUMN uuid TEXT")
            .execute(&self.0)
            .await;
        let _ = sqlx::query("ALTER TABLE agents ADD COLUMN nickname TEXT")
            .execute(&self.0)
            .await;
        let _ = sqlx::query("ALTER TABLE decisions ADD COLUMN country TEXT")
            .execute(&self.0)
            .await;
        let _ = sqlx::query("ALTER TABLE decisions ADD COLUMN asn_org TEXT")
            .execute(&self.0)
            .await;

        // Add butterfly_shield_enabled column to heartbeats (idempotent)
        let _ =
            sqlx::query("ALTER TABLE agent_heartbeats ADD COLUMN butterfly_shield_enabled INTEGER")
                .execute(&self.0)
                .await;

        // SSH successful login events table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ssh_logins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                username TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                country TEXT,
                asn_org TEXT,
                created_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_ssh_logins_created_at ON ssh_logins(created_at DESC)",
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS whitelist_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                note TEXT,
                created_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.0)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_whitelist_entries_created_at ON whitelist_entries(created_at DESC)",
        )
        .execute(&self.0)
        .await?;

        Ok(())
    }

    pub async fn insert_decision(
        &self,
        ip: &str,
        reason: &str,
        action: &str,
        source: &str,
    ) -> anyhow::Result<Option<i64>> {
        self.insert_decision_with_timestamp(ip, reason, action, source, None)
            .await
    }

    pub async fn insert_decision_with_timestamp(
        &self,
        ip: &str,
        reason: &str,
        action: &str,
        source: &str,
        timestamp: Option<&str>,
    ) -> anyhow::Result<Option<i64>> {
        if self.is_ip_whitelisted(ip).await? {
            return Ok(None);
        }

        let created_at = normalize_event_timestamp(timestamp);
        let geo = geoip::lookup(ip);
        let result = sqlx::query(
            r#"
            INSERT INTO decisions (ip, reason, action, source, country, asn_org, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(ip)
        .bind(reason)
        .bind(action)
        .bind(source)
        .bind(&geo.country)
        .bind(&geo.asn_org)
        .bind(&created_at)
        .execute(&self.0)
        .await?;

        Ok(Some(result.last_insert_rowid()))
    }

    pub async fn insert_telemetry_event(
        &self,
        ip: &str,
        reason: &str,
        level: &str,
        source: &str,
        log_path: Option<&str>,
    ) -> anyhow::Result<i64> {
        self.insert_telemetry_event_with_timestamp(ip, reason, level, source, log_path, None)
            .await
    }

    pub async fn insert_telemetry_event_with_timestamp(
        &self,
        ip: &str,
        reason: &str,
        level: &str,
        source: &str,
        log_path: Option<&str>,
        timestamp: Option<&str>,
    ) -> anyhow::Result<i64> {
        let created_at = normalize_event_timestamp(timestamp);
        let geo = geoip::lookup(ip);
        let result = sqlx::query(
            r#"
            INSERT INTO telemetry_events (ip, reason, level, source, log_path, country, asn_org, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(ip)
        .bind(reason)
        .bind(level)
        .bind(source)
        .bind(log_path)
        .bind(&geo.country)
        .bind(&geo.asn_org)
        .bind(&created_at)
        .execute(&self.0)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn insert_behavior_event(&self, event: &NewBehaviorEvent) -> anyhow::Result<i64> {
        let created_at = normalize_event_timestamp(event.timestamp.as_deref());
        let touched_paths_json = encode_json(&event.touched_paths)?;
        let protected_paths_json = encode_json(&event.protected_paths_touched)?;
        let reasons_json = encode_json(&event.reasons)?;
        let result = sqlx::query(
            r#"
            INSERT INTO behavior_events (
                agent_name,
                source,
                watched_root,
                pid,
                process_name,
                exe_path,
                command_line,
                correlation_hits,
                file_ops_created,
                file_ops_modified,
                file_ops_renamed,
                file_ops_deleted,
                touched_paths_json,
                protected_paths_json,
                bytes_written,
                io_rate_bytes_per_sec,
                score,
                reasons_json,
                level,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&event.agent_name)
        .bind(&event.source)
        .bind(&event.watched_root)
        .bind(event.pid.map(i64::from))
        .bind(&event.process_name)
        .bind(&event.exe_path)
        .bind(&event.command_line)
        .bind(i64::from(event.correlation_hits))
        .bind(i64::from(event.file_ops.created))
        .bind(i64::from(event.file_ops.modified))
        .bind(i64::from(event.file_ops.renamed))
        .bind(i64::from(event.file_ops.deleted))
        .bind(touched_paths_json)
        .bind(protected_paths_json)
        .bind(to_i64(event.bytes_written, "bytes_written")?)
        .bind(to_i64(
            event.io_rate_bytes_per_sec,
            "io_rate_bytes_per_sec",
        )?)
        .bind(i64::from(event.score))
        .bind(reasons_json)
        .bind(&event.level)
        .bind(created_at)
        .execute(&self.0)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn record_containment_event(
        &self,
        event: &NewContainmentEvent,
    ) -> anyhow::Result<i64> {
        let created_at = normalize_event_timestamp(event.timestamp.as_deref());
        let actions_json = encode_json(&event.actions)?;
        let outcomes_json = encode_json(&event.outcomes)?;

        let result = sqlx::query(
            r#"
            INSERT INTO containment_events (
                agent_name,
                state,
                previous_state,
                reason,
                watched_root,
                pid,
                score,
                actions_json,
                outcomes_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&event.agent_name)
        .bind(&event.state)
        .bind(&event.previous_state)
        .bind(&event.reason)
        .bind(&event.watched_root)
        .bind(event.pid.map(i64::from))
        .bind(i64::from(event.score))
        .bind(&actions_json)
        .bind(&outcomes_json)
        .bind(&created_at)
        .execute(&self.0)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO agent_containment_status (
                agent_name,
                state,
                previous_state,
                reason,
                watched_root,
                pid,
                score,
                actions_json,
                outcomes_json,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_name) DO UPDATE SET
                state = excluded.state,
                previous_state = excluded.previous_state,
                reason = excluded.reason,
                watched_root = excluded.watched_root,
                pid = excluded.pid,
                score = excluded.score,
                actions_json = excluded.actions_json,
                outcomes_json = excluded.outcomes_json,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&event.agent_name)
        .bind(&event.state)
        .bind(&event.previous_state)
        .bind(&event.reason)
        .bind(&event.watched_root)
        .bind(event.pid.map(i64::from))
        .bind(i64::from(event.score))
        .bind(actions_json)
        .bind(outcomes_json)
        .bind(created_at)
        .execute(&self.0)
        .await?;

        Ok(result.last_insert_rowid())
    }

    /// Record a successful SSH login event from an agent.
    pub async fn insert_ssh_login(
        &self,
        ip: &str,
        username: &str,
        agent_name: &str,
    ) -> anyhow::Result<i64> {
        self.insert_ssh_login_with_timestamp(ip, username, agent_name, None)
            .await
    }

    pub async fn insert_ssh_login_with_timestamp(
        &self,
        ip: &str,
        username: &str,
        agent_name: &str,
        timestamp: Option<&str>,
    ) -> anyhow::Result<i64> {
        let created_at = normalize_event_timestamp(timestamp);
        let geo = geoip::lookup(ip);
        let result = sqlx::query(
            r#"
            INSERT INTO ssh_logins (ip, username, agent_name, country, asn_org, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(ip)
        .bind(username)
        .bind(agent_name)
        .bind(&geo.country)
        .bind(&geo.asn_org)
        .bind(&created_at)
        .execute(&self.0)
        .await?;
        Ok(result.last_insert_rowid())
    }

    /// Return the most recent SSH login events (newest first).
    pub async fn list_ssh_logins(&self, limit: i64) -> anyhow::Result<Vec<SshLoginRow>> {
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                String,
            ),
        >(
            "SELECT id, ip, username, agent_name, country, asn_org, created_at \
             FROM ssh_logins ORDER BY created_at DESC, id DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, ip, username, agent_name, country, asn_org, created_at)| SshLoginRow {
                    id,
                    ip,
                    username,
                    agent_name,
                    country,
                    asn_org,
                    created_at,
                },
            )
            .collect())
    }

    pub async fn list_decisions_since(
        &self,
        since_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<DecisionRow>> {
        let rows =
            sqlx::query_as::<_, (i64, String, String, String, String, Option<String>, Option<String>, String, Option<String>)>(
                "SELECT id, ip, reason, action, source, country, asn_org, created_at, expires_at FROM decisions \
             WHERE id > ? ORDER BY id ASC LIMIT ?",
            )
            .bind(since_id)
            .bind(limit)
            .fetch_all(&self.0)
            .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, ip, reason, action, source, country, asn_org, created_at, expires_at)| {
                    DecisionRow {
                        id,
                        ip,
                        reason,
                        action,
                        source,
                        country,
                        asn_org,
                        created_at,
                        expires_at,
                    }
                },
            )
            .collect())
    }

    pub async fn list_local_decisions_since(
        &self,
        since_id: i64,
        limit: i64,
    ) -> anyhow::Result<Vec<DecisionRow>> {
        let rows = sqlx::query_as::<_, (i64, String, String, String, String, Option<String>, Option<String>, String, Option<String>)>(
            r#"
            SELECT d.id, d.ip, d.reason, d.action, d.source, d.country, d.asn_org, d.created_at, d.expires_at
            FROM decisions d
            LEFT JOIN agents a ON a.name = d.source
            WHERE d.id > ? AND (a.id IS NOT NULL OR d.source = 'campaign')
            ORDER BY d.id ASC
            LIMIT ?
            "#,
        )
        .bind(since_id)
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, ip, reason, action, source, country, asn_org, created_at, expires_at)| {
                    DecisionRow {
                        id,
                        ip,
                        reason,
                        action,
                        source,
                        country,
                        asn_org,
                        created_at,
                        expires_at,
                    }
                },
            )
            .collect())
    }

    pub async fn list_decisions(&self, limit: i64) -> anyhow::Result<Vec<DecisionRow>> {
        let rows = sqlx::query_as::<_, (i64, String, String, String, String, Option<String>, Option<String>, String, Option<String>)>(
            "SELECT id, ip, reason, action, source, country, asn_org, created_at, expires_at FROM decisions ORDER BY created_at DESC, id DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, ip, reason, action, source, country, asn_org, created_at, expires_at)| {
                    DecisionRow {
                        id,
                        ip,
                        reason,
                        action,
                        source,
                        country,
                        asn_org,
                        created_at,
                        expires_at,
                    }
                },
            )
            .collect())
    }

    pub async fn list_local_decisions(&self, limit: i64) -> anyhow::Result<Vec<DecisionRow>> {
        let rows = sqlx::query_as::<_, (i64, String, String, String, String, Option<String>, Option<String>, String, Option<String>)>(
            r#"
            SELECT d.id, d.ip, d.reason, d.action, d.source, d.country, d.asn_org, d.created_at, d.expires_at
            FROM decisions d
            LEFT JOIN agents a ON a.name = d.source
            WHERE a.id IS NOT NULL OR d.source = 'campaign'
            ORDER BY d.created_at DESC, d.id DESC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, ip, reason, action, source, country, asn_org, created_at, expires_at)| {
                    DecisionRow {
                        id,
                        ip,
                        reason,
                        action,
                        source,
                        country,
                        asn_org,
                        created_at,
                        expires_at,
                    }
                },
            )
            .collect())
    }

    pub async fn list_decisions_by_source(
        &self,
        source: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<DecisionRow>> {
        let rows = sqlx::query_as::<_, (i64, String, String, String, String, Option<String>, Option<String>, String, Option<String>)>(
            "SELECT id, ip, reason, action, source, country, asn_org, created_at, expires_at FROM decisions WHERE source = ? ORDER BY created_at DESC, id DESC LIMIT ?",
        )
        .bind(source)
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, ip, reason, action, source, country, asn_org, created_at, expires_at)| {
                    DecisionRow {
                        id,
                        ip,
                        reason,
                        action,
                        source,
                        country,
                        asn_org,
                        created_at,
                        expires_at,
                    }
                },
            )
            .collect())
    }

    pub async fn list_telemetry_by_source(
        &self,
        source: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<TelemetryRow>> {
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                Option<String>,
                String,
            ),
        >(
            "SELECT id, ip, reason, level, source, log_path, country, asn_org, created_at FROM telemetry_events WHERE source = ? ORDER BY created_at DESC, id DESC LIMIT ?",
        )
        .bind(source)
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, ip, reason, level, source, log_path, country, asn_org, created_at)| {
                    TelemetryRow {
                        id,
                        ip,
                        reason,
                        level,
                        source,
                        log_path,
                        country,
                        asn_org,
                        created_at,
                    }
                },
            )
            .collect())
    }

    pub async fn list_telemetry(&self, limit: i64) -> anyhow::Result<Vec<TelemetryRow>> {
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                Option<String>,
                String,
            ),
        >(
            "SELECT id, ip, reason, level, source, log_path, country, asn_org, created_at FROM telemetry_events ORDER BY created_at DESC, id DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, ip, reason, level, source, log_path, country, asn_org, created_at)| {
                    TelemetryRow {
                        id,
                        ip,
                        reason,
                        level,
                        source,
                        log_path,
                        country,
                        asn_org,
                        created_at,
                    }
                },
            )
            .collect())
    }

    pub async fn list_behavior_events(&self, limit: i64) -> anyhow::Result<Vec<BehaviorEventRow>> {
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                agent_name,
                source,
                watched_root,
                pid,
                process_name,
                exe_path,
                command_line,
                correlation_hits,
                file_ops_created,
                file_ops_modified,
                file_ops_renamed,
                file_ops_deleted,
                touched_paths_json,
                protected_paths_json,
                bytes_written,
                io_rate_bytes_per_sec,
                score,
                reasons_json,
                level,
                created_at
            FROM behavior_events
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        rows.into_iter()
            .map(|row| {
                let touched_paths_json: String = row.try_get("touched_paths_json")?;
                let protected_paths_json: String = row.try_get("protected_paths_json")?;
                let reasons_json: String = row.try_get("reasons_json")?;

                Ok(BehaviorEventRow {
                    id: row.try_get("id")?,
                    agent_name: row.try_get("agent_name")?,
                    source: row.try_get("source")?,
                    watched_root: row.try_get("watched_root")?,
                    pid: from_i64_opt_u32(row.try_get("pid")?, "behavior_events.pid")?,
                    process_name: row.try_get("process_name")?,
                    exe_path: row.try_get("exe_path")?,
                    command_line: row.try_get("command_line")?,
                    correlation_hits: from_i64_u32(
                        row.try_get("correlation_hits")?,
                        "behavior_events.correlation_hits",
                    )?,
                    file_ops: BehaviorFileOpsRow {
                        created: from_i64_u32(
                            row.try_get("file_ops_created")?,
                            "behavior_events.file_ops_created",
                        )?,
                        modified: from_i64_u32(
                            row.try_get("file_ops_modified")?,
                            "behavior_events.file_ops_modified",
                        )?,
                        renamed: from_i64_u32(
                            row.try_get("file_ops_renamed")?,
                            "behavior_events.file_ops_renamed",
                        )?,
                        deleted: from_i64_u32(
                            row.try_get("file_ops_deleted")?,
                            "behavior_events.file_ops_deleted",
                        )?,
                    },
                    touched_paths: decode_json(
                        &touched_paths_json,
                        "behavior_events.touched_paths_json",
                    )?,
                    protected_paths_touched: decode_json(
                        &protected_paths_json,
                        "behavior_events.protected_paths_json",
                    )?,
                    bytes_written: from_i64_u64(
                        row.try_get("bytes_written")?,
                        "behavior_events.bytes_written",
                    )?,
                    io_rate_bytes_per_sec: from_i64_u64(
                        row.try_get("io_rate_bytes_per_sec")?,
                        "behavior_events.io_rate_bytes_per_sec",
                    )?,
                    score: from_i64_u32(row.try_get("score")?, "behavior_events.score")?,
                    reasons: decode_json(&reasons_json, "behavior_events.reasons_json")?,
                    level: row.try_get("level")?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }

    pub async fn list_behavior_events_by_agent(
        &self,
        agent_name: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<BehaviorEventRow>> {
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                agent_name,
                source,
                watched_root,
                pid,
                process_name,
                exe_path,
                command_line,
                correlation_hits,
                file_ops_created,
                file_ops_modified,
                file_ops_renamed,
                file_ops_deleted,
                touched_paths_json,
                protected_paths_json,
                bytes_written,
                io_rate_bytes_per_sec,
                score,
                reasons_json,
                level,
                created_at
            FROM behavior_events
            WHERE agent_name = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            "#,
        )
        .bind(agent_name)
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        rows.into_iter()
            .map(|row| {
                let touched_paths_json: String = row.try_get("touched_paths_json")?;
                let protected_paths_json: String = row.try_get("protected_paths_json")?;
                let reasons_json: String = row.try_get("reasons_json")?;

                Ok(BehaviorEventRow {
                    id: row.try_get("id")?,
                    agent_name: row.try_get("agent_name")?,
                    source: row.try_get("source")?,
                    watched_root: row.try_get("watched_root")?,
                    pid: from_i64_opt_u32(row.try_get("pid")?, "behavior_events.pid")?,
                    process_name: row.try_get("process_name")?,
                    exe_path: row.try_get("exe_path")?,
                    command_line: row.try_get("command_line")?,
                    correlation_hits: from_i64_u32(
                        row.try_get("correlation_hits")?,
                        "behavior_events.correlation_hits",
                    )?,
                    file_ops: BehaviorFileOpsRow {
                        created: from_i64_u32(
                            row.try_get("file_ops_created")?,
                            "behavior_events.file_ops_created",
                        )?,
                        modified: from_i64_u32(
                            row.try_get("file_ops_modified")?,
                            "behavior_events.file_ops_modified",
                        )?,
                        renamed: from_i64_u32(
                            row.try_get("file_ops_renamed")?,
                            "behavior_events.file_ops_renamed",
                        )?,
                        deleted: from_i64_u32(
                            row.try_get("file_ops_deleted")?,
                            "behavior_events.file_ops_deleted",
                        )?,
                    },
                    touched_paths: decode_json(
                        &touched_paths_json,
                        "behavior_events.touched_paths_json",
                    )?,
                    protected_paths_touched: decode_json(
                        &protected_paths_json,
                        "behavior_events.protected_paths_json",
                    )?,
                    bytes_written: from_i64_u64(
                        row.try_get("bytes_written")?,
                        "behavior_events.bytes_written",
                    )?,
                    io_rate_bytes_per_sec: from_i64_u64(
                        row.try_get("io_rate_bytes_per_sec")?,
                        "behavior_events.io_rate_bytes_per_sec",
                    )?,
                    score: from_i64_u32(row.try_get("score")?, "behavior_events.score")?,
                    reasons: decode_json(&reasons_json, "behavior_events.reasons_json")?,
                    level: row.try_get("level")?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }

    pub async fn list_containment_statuses(
        &self,
        limit: i64,
    ) -> anyhow::Result<Vec<ContainmentStatusRow>> {
        let rows = sqlx::query_as::<
            _,
            (
                String,
                String,
                Option<String>,
                String,
                String,
                Option<i64>,
                i64,
                String,
                String,
                String,
            ),
        >(
            r#"
            SELECT
                agent_name,
                state,
                previous_state,
                reason,
                watched_root,
                pid,
                score,
                actions_json,
                outcomes_json,
                updated_at
            FROM agent_containment_status
            ORDER BY updated_at DESC, agent_name ASC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        rows.into_iter()
            .map(
                |(
                    agent_name,
                    state,
                    previous_state,
                    reason,
                    watched_root,
                    pid,
                    score,
                    actions_json,
                    outcomes_json,
                    updated_at,
                )| {
                    Ok(ContainmentStatusRow {
                        agent_name,
                        state,
                        previous_state,
                        reason,
                        watched_root,
                        pid: from_i64_opt_u32(pid, "agent_containment_status.pid")?,
                        score: from_i64_u32(score, "agent_containment_status.score")?,
                        actions: decode_json(
                            &actions_json,
                            "agent_containment_status.actions_json",
                        )?,
                        outcomes: decode_json(
                            &outcomes_json,
                            "agent_containment_status.outcomes_json",
                        )?,
                        updated_at,
                    })
                },
            )
            .collect()
    }

    pub async fn list_containment_events_by_agent(
        &self,
        agent_name: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<ContainmentEventRow>> {
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                String,
                Option<String>,
                String,
                String,
                Option<i64>,
                i64,
                String,
                String,
                String,
            ),
        >(
            r#"
            SELECT
                id,
                agent_name,
                state,
                previous_state,
                reason,
                watched_root,
                pid,
                score,
                actions_json,
                outcomes_json,
                created_at
            FROM containment_events
            WHERE agent_name = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            "#,
        )
        .bind(agent_name)
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        rows.into_iter()
            .map(
                |(
                    id,
                    agent_name,
                    state,
                    previous_state,
                    reason,
                    watched_root,
                    pid,
                    score,
                    actions_json,
                    outcomes_json,
                    created_at,
                )| {
                    Ok(ContainmentEventRow {
                        id,
                        agent_name,
                        state,
                        previous_state,
                        reason,
                        watched_root,
                        pid: from_i64_opt_u32(pid, "containment_events.pid")?,
                        score: from_i64_u32(score, "containment_events.score")?,
                        actions: decode_json(&actions_json, "containment_events.actions_json")?,
                        outcomes: decode_json(&outcomes_json, "containment_events.outcomes_json")?,
                        created_at,
                    })
                },
            )
            .collect()
    }

    pub async fn list_whitelist_entries(
        &self,
        limit: i64,
    ) -> anyhow::Result<Vec<WhitelistEntryRow>> {
        let rows = sqlx::query_as::<_, (i64, String, Option<String>, String)>(
            "SELECT id, ip, note, created_at FROM whitelist_entries ORDER BY created_at DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(id, ip, note, created_at)| WhitelistEntryRow {
                id,
                ip,
                note,
                created_at,
            })
            .collect())
    }

    pub async fn is_ip_whitelisted(&self, ip: &str) -> anyhow::Result<bool> {
        let patterns = sqlx::query_as::<_, (String,)>("SELECT ip FROM whitelist_entries")
            .fetch_all(&self.0)
            .await?;

        Ok(patterns
            .into_iter()
            .any(|(pattern,)| pattern_covers_pattern(&pattern, ip)))
    }

    pub async fn upsert_whitelist_entry(
        &self,
        ip: &str,
        note: Option<&str>,
    ) -> anyhow::Result<WhitelistEntryRow> {
        let ip = canonicalize_ip_pattern(ip)
            .ok_or_else(|| anyhow::anyhow!("invalid IP/CIDR pattern"))?;
        let created_at = Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO whitelist_entries (ip, note, created_at)
            VALUES (?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                note = excluded.note
            "#,
        )
        .bind(&ip)
        .bind(note)
        .bind(&created_at)
        .execute(&self.0)
        .await?;

        let covered_decision_ids =
            sqlx::query_as::<_, (i64, String)>("SELECT id, ip FROM decisions")
                .fetch_all(&self.0)
                .await?
                .into_iter()
                .filter_map(|(id, decision_ip)| {
                    pattern_covers_pattern(&ip, &decision_ip).then_some(id)
                })
                .collect::<Vec<_>>();

        for id in covered_decision_ids {
            sqlx::query("DELETE FROM decisions WHERE id = ?")
                .bind(id)
                .execute(&self.0)
                .await?;
        }

        let (id, ip, note, created_at) =
            sqlx::query_as::<_, (i64, String, Option<String>, String)>(
                "SELECT id, ip, note, created_at FROM whitelist_entries WHERE ip = ?",
            )
            .bind(&ip)
            .fetch_one(&self.0)
            .await?;

        Ok(WhitelistEntryRow {
            id,
            ip,
            note,
            created_at,
        })
    }

    pub async fn delete_whitelist_entry(&self, id: i64) -> anyhow::Result<bool> {
        let result = sqlx::query("DELETE FROM whitelist_entries WHERE id = ?")
            .bind(id)
            .execute(&self.0)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn backfill_decision_geoip_unknowns(&self) -> anyhow::Result<u64> {
        let ips = sqlx::query_as::<_, (String,)>(
            r#"
            SELECT DISTINCT ip
            FROM decisions
            WHERE country IS NULL
               OR asn_org IS NULL
               OR TRIM(country) = ''
               OR TRIM(asn_org) = ''
            "#,
        )
        .fetch_all(&self.0)
        .await?;

        let mut updated = 0u64;
        for (ip,) in ips {
            let geo = geoip::lookup(&ip);
            let result = sqlx::query(
                r#"
                UPDATE decisions
                SET
                    country = CASE WHEN country IS NULL OR TRIM(country) = '' THEN ? ELSE country END,
                    asn_org = CASE WHEN asn_org IS NULL OR TRIM(asn_org) = '' THEN ? ELSE asn_org END
                WHERE ip = ?
                  AND (
                    country IS NULL OR TRIM(country) = ''
                    OR asn_org IS NULL OR TRIM(asn_org) = ''
                  )
                "#,
            )
                .bind(geo.country)
                .bind(geo.asn_org)
                .bind(ip)
                .execute(&self.0)
                .await?;
            updated += result.rows_affected();
        }

        Ok(updated)
    }

    pub async fn backfill_decision_geoip_for_source(&self, source: &str) -> anyhow::Result<u64> {
        let ips = sqlx::query_as::<_, (String,)>(
            r#"
            SELECT DISTINCT ip
            FROM decisions
            WHERE source = ?
              AND (
                country IS NULL OR TRIM(country) = ''
                OR asn_org IS NULL OR TRIM(asn_org) = ''
              )
            "#,
        )
        .bind(source)
        .fetch_all(&self.0)
        .await?;

        let mut updated = 0u64;
        for (ip,) in ips {
            let geo = geoip::lookup(&ip);
            let result = sqlx::query(
                r#"
                UPDATE decisions
                SET
                    country = CASE WHEN country IS NULL OR TRIM(country) = '' THEN ? ELSE country END,
                    asn_org = CASE WHEN asn_org IS NULL OR TRIM(asn_org) = '' THEN ? ELSE asn_org END
                WHERE source = ?
                  AND ip = ?
                  AND (
                    country IS NULL OR TRIM(country) = ''
                    OR asn_org IS NULL OR TRIM(asn_org) = ''
                  )
                "#,
            )
            .bind(geo.country)
            .bind(geo.asn_org)
            .bind(source)
            .bind(ip)
            .execute(&self.0)
            .await?;
            updated += result.rows_affected();
        }

        Ok(updated)
    }

    pub async fn insert_agent(
        &self,
        name: &str,
        token_hash: &str,
        uuid: Option<&str>,
    ) -> anyhow::Result<i64> {
        let created_at = Utc::now().to_rfc3339();
        let result = sqlx::query(
            r#"
            INSERT INTO agents (name, token_hash, created_at, uuid)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                token_hash = excluded.token_hash,
                uuid = COALESCE(excluded.uuid, agents.uuid)
            "#,
        )
        .bind(name)
        .bind(token_hash)
        .bind(&created_at)
        .bind(uuid)
        .execute(&self.0)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn update_agent_nickname(&self, id: i64, nickname: &str) -> anyhow::Result<()> {
        sqlx::query("UPDATE agents SET nickname = ? WHERE id = ?")
            .bind(nickname)
            .bind(id)
            .execute(&self.0)
            .await?;
        Ok(())
    }

    pub async fn delete_agent(&self, id: i64) -> anyhow::Result<()> {
        // Fetch the agent's name first so we can clean up heartbeats
        let row = sqlx::query_as::<_, (String,)>("SELECT name FROM agents WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.0)
            .await?;

        if let Some((name,)) = row {
            sqlx::query("DELETE FROM agent_heartbeats WHERE agent_name = ?")
                .bind(&name)
                .execute(&self.0)
                .await?;
        }

        sqlx::query("DELETE FROM agents WHERE id = ?")
            .bind(id)
            .execute(&self.0)
            .await?;

        Ok(())
    }

    pub async fn get_agent_name_by_id(&self, id: i64) -> anyhow::Result<Option<String>> {
        let row = sqlx::query_as::<_, (String,)>("SELECT name FROM agents WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.0)
            .await?;

        Ok(row.map(|(name,)| name))
    }

    pub async fn find_agent_by_token_hash(&self, hash: &str) -> anyhow::Result<Option<AgentRow>> {
        let row = sqlx::query_as::<_, (i64, String, String, String)>(
            "SELECT id, name, token_hash, created_at FROM agents WHERE token_hash = ?",
        )
        .bind(hash)
        .fetch_optional(&self.0)
        .await?;

        Ok(row.map(|(id, name, token_hash, created_at)| AgentRow {
            id,
            name,
            token_hash,
            created_at,
        }))
    }

    pub async fn list_agents_with_last_seen(
        &self,
        limit: i64,
    ) -> anyhow::Result<Vec<AgentStatusRow>> {
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                Option<String>,
                Option<String>,
                String,
                Option<String>,
                Option<i64>,
            ),
        >(
            r#"
            SELECT
                a.id,
                a.name,
                a.uuid,
                a.nickname,
                a.created_at,
                h.last_heartbeat_at as last_seen_at,
                h.butterfly_shield_enabled
            FROM agents a
            LEFT JOIN agent_heartbeats h ON h.agent_name = a.name
            ORDER BY a.created_at DESC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, name, uuid, nickname, created_at, last_seen_at, butterfly_shield_enabled)| {
                    AgentStatusRow {
                        id,
                        name,
                        uuid,
                        nickname,
                        created_at,
                        last_seen_at,
                        butterfly_shield_enabled: butterfly_shield_enabled.map(|v| v != 0),
                    }
                },
            )
            .collect())
    }

    pub async fn list_community_ips(&self, limit: i64) -> anyhow::Result<Vec<CommunityIpRow>> {
        let rows = sqlx::query_as::<_, (String, String, Option<i64>, Option<String>, i64, String)>(
            r#"
            SELECT
                d.ip,
                d.source,
                a.id,
                a.nickname,
                COUNT(*) as sightings,
                MAX(d.created_at) as last_seen_at
            FROM decisions d
            LEFT JOIN agents a ON a.name = d.source
            GROUP BY d.ip, d.source
            ORDER BY last_seen_at DESC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(ip, source, agent_id, nickname, sightings, last_seen_at)| CommunityIpRow {
                    ip,
                    source_label: source_label(&source, nickname),
                    kind: source_kind(&source, agent_id).to_string(),
                    source,
                    sightings,
                    last_seen_at,
                },
            )
            .collect())
    }

    pub async fn list_community_feeds(&self) -> anyhow::Result<Vec<CommunityFeedRow>> {
        let rows = sqlx::query_as::<_, (String, Option<i64>, Option<String>, i64, String, String)>(
            r#"
            SELECT
                d.source,
                a.id,
                a.nickname,
                COUNT(DISTINCT d.ip) as ip_count,
                MIN(d.created_at) as first_seen_at,
                MAX(d.created_at) as last_seen_at
            FROM decisions d
            LEFT JOIN agents a ON a.name = d.source
            GROUP BY d.source, a.id, a.nickname
            ORDER BY
                CASE
                    WHEN d.source = 'campaign' THEN 0
                    WHEN a.id IS NOT NULL THEN 1
                    ELSE 2
                END,
                last_seen_at DESC
            "#,
        )
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(source, agent_id, nickname, ip_count, first_seen_at, last_seen_at)| {
                    CommunityFeedRow {
                        source_label: source_label(&source, nickname),
                        kind: source_kind(&source, agent_id).to_string(),
                        source,
                        ip_count,
                        first_seen_at,
                        last_seen_at,
                    }
                },
            )
            .collect())
    }

    pub async fn list_community_feed_ips(
        &self,
        source: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<CommunityFeedIpRow>> {
        let rows = sqlx::query_as::<_, (String, String, i64, String, String)>(
            r#"
            SELECT
                d.ip,
                MAX(d.reason) as reason,
                COUNT(*) as sightings,
                MIN(d.created_at) as first_seen_at,
                MAX(d.created_at) as last_seen_at
            FROM decisions d
            WHERE d.source = ?
            GROUP BY d.ip
            ORDER BY last_seen_at DESC
            LIMIT ?
            "#,
        )
        .bind(source)
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(ip, reason, sightings, first_seen_at, last_seen_at)| CommunityFeedIpRow {
                    ip,
                    reason,
                    sightings,
                    first_seen_at,
                    last_seen_at,
                },
            )
            .collect())
    }

    pub async fn lookup_ip_activity(
        &self,
        ip: &str,
        history_limit: i64,
    ) -> anyhow::Result<IpLookupResponse> {
        let local_history_rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                String,
                String,
                Option<i64>,
                Option<String>,
                Option<String>,
                Option<String>,
                Option<String>,
                String,
            ),
        >(
            r#"
            SELECT
                t.id,
                t.source,
                t.reason,
                t.level,
                a.id,
                COALESCE(NULLIF(a.nickname, ''), a.name) as agent_display_name,
                t.log_path,
                t.country,
                t.asn_org,
                t.created_at
            FROM telemetry_events t
            LEFT JOIN agents a ON a.name = t.source
            WHERE t.ip = ?
            ORDER BY t.created_at DESC, t.id DESC
            LIMIT ?
            "#,
        )
        .bind(ip)
        .bind(history_limit)
        .fetch_all(&self.0)
        .await?;

        let local_history = local_history_rows
            .into_iter()
            .map(
                |(
                    id,
                    source,
                    reason,
                    level,
                    agent_id,
                    agent_display_name,
                    log_path,
                    country,
                    asn_org,
                    created_at,
                )| IpLookupEventRow {
                    id,
                    source: source.clone(),
                    source_label: source_label(&source, agent_display_name),
                    agent_id,
                    reason,
                    level,
                    log_path,
                    country: country.and_then(normalize_lookup_geo),
                    asn_org: asn_org.and_then(normalize_lookup_geo),
                    created_at,
                },
            )
            .collect::<Vec<_>>();

        let machine_summary_rows = sqlx::query_as::<
            _,
            (
                String,
                Option<i64>,
                Option<String>,
                i64,
                i64,
                i64,
                i64,
                String,
                String,
                Option<String>,
            ),
        >(
            r#"
            SELECT
                t.source,
                a.id,
                COALESCE(NULLIF(a.nickname, ''), a.name) as agent_display_name,
                COUNT(*) as event_count,
                SUM(CASE WHEN t.level = 'alert' THEN 1 ELSE 0 END) as alert_count,
                SUM(CASE WHEN t.level = 'listed' THEN 1 ELSE 0 END) as listed_count,
                SUM(CASE WHEN t.level = 'block' THEN 1 ELSE 0 END) as block_count,
                MIN(t.created_at) as first_seen_at,
                MAX(t.created_at) as last_seen_at,
                (
                    SELECT t2.reason
                    FROM telemetry_events t2
                    WHERE t2.ip = t.ip
                      AND t2.source = t.source
                    ORDER BY t2.created_at DESC, t2.id DESC
                    LIMIT 1
                ) as last_reason
            FROM telemetry_events t
            LEFT JOIN agents a ON a.name = t.source
            WHERE t.ip = ?
            GROUP BY t.source, a.id, a.nickname, a.name
            ORDER BY MAX(t.created_at) DESC, t.source ASC
            "#,
        )
        .bind(ip)
        .fetch_all(&self.0)
        .await?;

        let machine_summaries = machine_summary_rows
            .into_iter()
            .map(
                |(
                    source,
                    agent_id,
                    agent_display_name,
                    event_count,
                    alert_count,
                    listed_count,
                    block_count,
                    first_seen_at,
                    last_seen_at,
                    last_reason,
                )| IpLookupMachineSummaryRow {
                    agent_id,
                    source: source.clone(),
                    source_label: source_label(&source, agent_display_name),
                    event_count,
                    alert_count,
                    listed_count,
                    block_count,
                    first_seen_at,
                    last_seen_at,
                    last_reason: last_reason.unwrap_or_else(|| "Unknown".to_string()),
                },
            )
            .collect::<Vec<_>>();

        let decision_rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                String,
                String,
                Option<i64>,
                Option<String>,
                Option<String>,
                Option<String>,
                String,
                Option<String>,
            ),
        >(
            r#"
            SELECT
                d.id,
                d.source,
                d.reason,
                d.action,
                a.id,
                COALESCE(NULLIF(a.nickname, ''), a.name) as agent_display_name,
                d.country,
                d.asn_org,
                d.created_at,
                d.expires_at
            FROM decisions d
            LEFT JOIN agents a ON a.name = d.source
            WHERE d.ip = ?
              AND (a.id IS NOT NULL OR d.source = 'campaign')
            ORDER BY d.created_at DESC, d.id DESC
            LIMIT ?
            "#,
        )
        .bind(ip)
        .bind(history_limit)
        .fetch_all(&self.0)
        .await?;

        let decision_history = decision_rows
            .into_iter()
            .map(
                |(
                    id,
                    source,
                    reason,
                    action,
                    agent_id,
                    agent_display_name,
                    country,
                    asn_org,
                    created_at,
                    expires_at,
                )| IpLookupDecisionRow {
                    id,
                    source: source.clone(),
                    source_label: source_label(&source, agent_display_name),
                    agent_id,
                    reason,
                    action,
                    country: country.and_then(normalize_lookup_geo),
                    asn_org: asn_org.and_then(normalize_lookup_geo),
                    created_at,
                    expires_at,
                },
            )
            .collect::<Vec<_>>();

        let community_candidate_rows =
            sqlx::query_as::<_, (String, String, String, i64, String, String)>(
                r#"
            SELECT
                d.ip,
                d.source,
                MAX(d.reason) as reason,
                COUNT(*) as sightings,
                MIN(d.created_at) as first_seen_at,
                MAX(d.created_at) as last_seen_at
            FROM decisions d
            LEFT JOIN agents a ON a.name = d.source
            WHERE a.id IS NULL
              AND d.source != 'campaign'
              AND (d.ip = ? OR instr(d.ip, '/') > 0)
            GROUP BY d.ip, d.source
            ORDER BY last_seen_at DESC, d.source ASC
            "#,
            )
            .bind(ip)
            .fetch_all(&self.0)
            .await?;

        let mut community_matches = community_candidate_rows
            .into_iter()
            .filter(|(pattern, _, _, _, _, _)| pattern_covers_pattern(pattern, ip))
            .map(
                |(matched_entry, source, reason, sightings, first_seen_at, last_seen_at)| {
                    IpLookupCommunityMatchRow {
                        source,
                        matched_entry,
                        reason,
                        sightings,
                        first_seen_at,
                        last_seen_at,
                    }
                },
            )
            .collect::<Vec<_>>();

        community_matches.sort_by(|a, b| {
            b.last_seen_at
                .cmp(&a.last_seen_at)
                .then_with(|| a.source.cmp(&b.source))
                .then_with(|| a.matched_entry.cmp(&b.matched_entry))
        });

        let geo = geoip::lookup(ip);
        let country = local_history
            .iter()
            .find_map(|row| row.country.clone())
            .or_else(|| decision_history.iter().find_map(|row| row.country.clone()))
            .or_else(|| normalize_lookup_geo(geo.country));
        let asn_org = local_history
            .iter()
            .find_map(|row| row.asn_org.clone())
            .or_else(|| decision_history.iter().find_map(|row| row.asn_org.clone()))
            .or_else(|| normalize_lookup_geo(geo.asn_org));

        Ok(IpLookupResponse {
            ip: ip.to_string(),
            country,
            asn_org,
            local_history,
            decision_history,
            machine_summaries,
            community_matches,
        })
    }

    /// Detect coordinated campaigns by analysing recent telemetry from all agents.
    ///
    /// Returns a list of `(ip, reason_category)` pairs that are part of a campaign:
    /// the same attack category was seen from `min_distinct_ips` or more distinct
    /// source IPs across at least `min_distinct_agents` different agents within the
    /// last `window_secs` seconds.
    ///
    /// Only IPs that do **not** already have a decision in the database are returned,
    /// so callers can immediately create auto-block decisions for them.
    pub async fn detect_campaign_ips(
        &self,
        window_secs: i64,
        min_distinct_ips: usize,
        min_distinct_agents: usize,
    ) -> anyhow::Result<Vec<(String, String)>> {
        // Fetch recent telemetry for all agents.
        let rows = sqlx::query_as::<_, (String, String, String)>(
            r#"
            SELECT ip, reason, source
            FROM telemetry_events
            WHERE datetime(created_at) > datetime('now', '-' || ? || ' seconds')
              AND level IN ('alert', 'block')
            "#,
        )
        .bind(window_secs)
        .fetch_all(&self.0)
        .await?;

        // Build: category → (set of IPs, set of agent sources).
        use std::collections::{HashMap, HashSet};
        let mut cat_ips: HashMap<String, HashSet<String>> = HashMap::new();
        let mut cat_agents: HashMap<String, HashSet<String>> = HashMap::new();
        // Also track IP → category for result building.
        let mut ip_categories: HashMap<String, String> = HashMap::new();

        for (ip, reason, source) in &rows {
            let cat = normalize_reason_category(reason).to_string();
            cat_ips.entry(cat.clone()).or_default().insert(ip.clone());
            cat_agents
                .entry(cat.clone())
                .or_default()
                .insert(source.clone());
            ip_categories.insert(ip.clone(), cat);
        }

        // Find campaign categories.
        let campaign_cats: HashSet<String> = cat_ips
            .iter()
            .filter(|(cat, ips)| {
                ips.len() >= min_distinct_ips
                    && cat_agents.get(*cat).map(|a| a.len()).unwrap_or(0) >= min_distinct_agents
            })
            .map(|(cat, _)| cat.clone())
            .collect();

        if campaign_cats.is_empty() {
            return Ok(vec![]);
        }

        // Gather all IPs from campaign categories.
        let mut candidates: Vec<(String, String)> = Vec::new();
        for (ip, cat) in &ip_categories {
            if campaign_cats.contains(cat) {
                candidates.push((ip.clone(), cat.clone()));
            }
        }

        // Exclude IPs already in the decisions table.
        let already_blocked: HashSet<String> =
            sqlx::query_as::<_, (String,)>("SELECT DISTINCT ip FROM decisions")
                .fetch_all(&self.0)
                .await?
                .into_iter()
                .map(|(ip,)| ip)
                .collect();

        Ok(candidates
            .into_iter()
            .filter(|(ip, _)| !already_blocked.contains(ip))
            .collect())
    }

    pub async fn compute_shared_risk_profile(
        &self,
        window_secs: i64,
    ) -> anyhow::Result<SharedRiskProfileRow> {
        use std::collections::{HashMap, HashSet};

        let window_secs = window_secs.max(60);
        let rows = sqlx::query_as::<_, (String, String, String, String)>(
            r#"
            SELECT ip, reason, level, source
            FROM telemetry_events
            WHERE datetime(created_at) > datetime('now', '-' || ? || ' seconds')
              AND level IN ('alert', 'block', 'listed')
            "#,
        )
        .bind(window_secs)
        .fetch_all(&self.0)
        .await?;

        let mut global_weight = 0.0f64;
        let mut by_category: HashMap<String, (HashSet<String>, HashSet<String>, u32, f64)> =
            HashMap::new();

        for (ip, reason, level, source) in rows {
            let category = normalize_reason_category(&reason).to_string();
            let weight = telemetry_level_weight(&level);
            global_weight += weight;

            let entry = by_category
                .entry(category)
                .or_insert_with(|| (HashSet::new(), HashSet::new(), 0_u32, 0.0_f64));
            entry.0.insert(ip);
            entry.1.insert(source);
            entry.2 += 1;
            entry.3 += weight;
        }

        let global_risk_score = (global_weight / 30.0).clamp(0.0, 1.0);
        let global_threshold_multiplier = 1.0 - global_risk_score * 0.5;

        let mut categories = by_category
            .into_iter()
            .filter_map(|(category, (ips, agents, event_count, weighted_events))| {
                let distinct_ips = ips.len() as u32;
                let distinct_agents = agents.len() as u32;

                if distinct_agents < 2 {
                    return None;
                }

                if distinct_ips >= 3 {
                    return Some(SharedRiskCategoryRow {
                        category,
                        distinct_ips,
                        distinct_agents,
                        event_count,
                        threshold_multiplier: 0.25,
                        force_threshold: Some(1),
                        label: "shared:campaign".to_string(),
                    });
                }

                if event_count >= 5 || weighted_events >= 6.0 {
                    return Some(SharedRiskCategoryRow {
                        category,
                        distinct_ips,
                        distinct_agents,
                        event_count,
                        threshold_multiplier: 0.5,
                        force_threshold: None,
                        label: "shared:surge".to_string(),
                    });
                }

                None
            })
            .collect::<Vec<_>>();

        categories.sort_by(|a, b| {
            a.force_threshold
                .unwrap_or(u32::MAX)
                .cmp(&b.force_threshold.unwrap_or(u32::MAX))
                .then(b.event_count.cmp(&a.event_count))
                .then(a.category.cmp(&b.category))
        });

        Ok(SharedRiskProfileRow {
            generated_at: Utc::now().to_rfc3339(),
            window_secs,
            global_risk_score,
            global_threshold_multiplier,
            categories,
        })
    }

    pub async fn upsert_agent_heartbeat(
        &self,
        agent_name: &str,
        butterfly_shield_enabled: Option<bool>,
    ) -> anyhow::Result<()> {
        let now = Utc::now().to_rfc3339();
        let flag: Option<i64> = butterfly_shield_enabled.map(|v| v as i64);
        sqlx::query(
            r#"
            INSERT INTO agent_heartbeats (agent_name, last_heartbeat_at, butterfly_shield_enabled)
            VALUES (?, ?, ?)
            ON CONFLICT(agent_name) DO UPDATE SET
                last_heartbeat_at = excluded.last_heartbeat_at,
                butterfly_shield_enabled = excluded.butterfly_shield_enabled
            "#,
        )
        .bind(agent_name)
        .bind(now)
        .bind(flag)
        .execute(&self.0)
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_insert_and_list_decisions() {
        // Create an in-memory SQLite database for testing
        let db = Db::new(":memory:").await.expect("Failed to create test DB");

        // Insert some test decisions
        let id1 = db
            .insert_decision_with_timestamp(
                "192.168.1.1",
                "Test reason 1",
                "block",
                "agent",
                Some("2026-03-11T09:05:00+00:00"),
            )
            .await
            .expect("Failed to insert decision 1")
            .expect("decision should be inserted");
        assert!(id1 > 0);

        let id2 = db
            .insert_decision_with_timestamp(
                "192.168.1.2",
                "Test reason 2",
                "block",
                "agent",
                Some("2026-03-11T09:00:00+00:00"),
            )
            .await
            .expect("Failed to insert decision 2")
            .expect("decision should be inserted");
        assert!(id2 > id1);

        // List decisions
        let decisions = db
            .list_decisions(100)
            .await
            .expect("Failed to list decisions");

        assert_eq!(decisions.len(), 2);
        assert_eq!(decisions[0].ip, "192.168.1.1");
        assert_eq!(decisions[1].ip, "192.168.1.2");
        assert_eq!(decisions[0].reason, "Test reason 1");
        assert_eq!(decisions[1].reason, "Test reason 2");
        assert_eq!(decisions[0].created_at, "2026-03-11T09:05:00+00:00");
        assert_eq!(decisions[1].created_at, "2026-03-11T09:00:00+00:00");
    }

    #[tokio::test]
    async fn list_local_decisions_excludes_community_feeds() {
        let db = Db::new(":memory:").await.expect("Failed to create test DB");

        db.insert_agent("agent-alpha", "token-a", None)
            .await
            .unwrap();

        db.insert_decision_with_timestamp(
            "203.0.113.44",
            "Manual block",
            "block",
            "agent-alpha",
            Some("2026-03-11T09:05:00+00:00"),
        )
        .await
        .unwrap()
        .expect("agent decision should be inserted");
        db.insert_decision_with_timestamp(
            "203.0.113.45",
            "Campaign auto-block: SSH brute force",
            "block",
            "campaign",
            Some("2026-03-11T09:04:00+00:00"),
        )
        .await
        .unwrap()
        .expect("campaign decision should be inserted");
        db.insert_decision_with_timestamp(
            "203.0.113.46",
            "ipsum_feed",
            "block",
            "ipsum_feed",
            Some("2026-03-11T09:06:00+00:00"),
        )
        .await
        .unwrap()
        .expect("community decision should be inserted");

        let decisions = db.list_local_decisions(10).await.unwrap();
        assert_eq!(decisions.len(), 2);
        assert_eq!(decisions[0].source, "agent-alpha");
        assert_eq!(decisions[1].source, "campaign");

        let incremental = db.list_local_decisions_since(0, 10).await.unwrap();
        assert_eq!(incremental.len(), 2);
        assert!(incremental.iter().all(|row| row.source != "ipsum_feed"));
    }

    #[tokio::test]
    async fn list_community_feeds_includes_agent_and_campaign_sources() {
        let db = Db::new(":memory:").await.expect("Failed to create test DB");

        let agent_id = db
            .insert_agent("agent-alpha", "token-a", None)
            .await
            .unwrap();
        db.update_agent_nickname(agent_id, "Tokyo edge")
            .await
            .unwrap();

        db.insert_decision_with_timestamp(
            "203.0.113.10",
            "feed",
            "block",
            "ipsum_feed",
            Some("2026-03-11T09:00:00+00:00"),
        )
        .await
        .unwrap()
        .expect("feed decision should be inserted");
        db.insert_decision_with_timestamp(
            "203.0.113.11",
            "agent",
            "block",
            "agent-alpha",
            Some("2026-03-11T09:01:00+00:00"),
        )
        .await
        .unwrap()
        .expect("agent decision should be inserted");
        db.insert_decision_with_timestamp(
            "203.0.113.12",
            "campaign",
            "block",
            "campaign",
            Some("2026-03-11T09:02:00+00:00"),
        )
        .await
        .unwrap()
        .expect("campaign decision should be inserted");

        let sources = db.list_community_feeds().await.unwrap();

        assert_eq!(sources.len(), 3);
        assert_eq!(sources[0].source, "campaign");
        assert_eq!(sources[0].kind, "campaign");
        assert_eq!(sources[0].source_label, "Campaign auto-block");
        assert_eq!(sources[1].source, "agent-alpha");
        assert_eq!(sources[1].kind, "agent");
        assert_eq!(sources[1].source_label, "Tokyo edge");
        assert_eq!(sources[2].source, "ipsum_feed");
        assert_eq!(sources[2].kind, "community");
    }

    #[tokio::test]
    async fn list_telemetry_orders_by_preserved_event_timestamp() {
        let db = Db::new(":memory:").await.expect("Failed to create test DB");

        db.insert_telemetry_event_with_timestamp(
            "10.0.0.1",
            "Invalid SSH user",
            "alert",
            "agent-a",
            None,
            Some("2026-03-11T09:10:00+00:00"),
        )
        .await
        .unwrap();
        db.insert_telemetry_event_with_timestamp(
            "10.0.0.2",
            "Invalid SSH user",
            "alert",
            "agent-a",
            None,
            Some("2026-03-11T09:00:00+00:00"),
        )
        .await
        .unwrap();

        let telemetry = db.list_telemetry_by_source("agent-a", 10).await.unwrap();
        assert_eq!(telemetry.len(), 2);
        assert_eq!(telemetry[0].ip, "10.0.0.1");
        assert_eq!(telemetry[0].created_at, "2026-03-11T09:10:00+00:00");
        assert_eq!(telemetry[1].ip, "10.0.0.2");
        assert_eq!(telemetry[1].created_at, "2026-03-11T09:00:00+00:00");
    }

    #[tokio::test]
    async fn list_ssh_logins_orders_by_preserved_event_timestamp() {
        let db = Db::new(":memory:").await.expect("Failed to create test DB");

        db.insert_ssh_login_with_timestamp(
            "198.51.100.10",
            "alice",
            "agent-a",
            Some("2026-03-11T09:10:00+00:00"),
        )
        .await
        .unwrap();
        db.insert_ssh_login_with_timestamp(
            "198.51.100.11",
            "bob",
            "agent-a",
            Some("2026-03-11T09:00:00+00:00"),
        )
        .await
        .unwrap();

        let logins = db.list_ssh_logins(10).await.unwrap();
        assert_eq!(logins.len(), 2);
        assert_eq!(logins[0].ip, "198.51.100.10");
        assert_eq!(logins[0].created_at, "2026-03-11T09:10:00+00:00");
        assert_eq!(logins[1].ip, "198.51.100.11");
        assert_eq!(logins[1].created_at, "2026-03-11T09:00:00+00:00");
    }

    #[tokio::test]
    async fn shared_risk_profile_exposes_campaign_category() {
        let db = Db::new(":memory:").await.expect("Failed to create test DB");

        db.insert_telemetry_event("10.0.0.1", "Invalid SSH user", "alert", "agent-a", None)
            .await
            .unwrap();
        db.insert_telemetry_event("10.0.0.2", "Invalid SSH user", "alert", "agent-b", None)
            .await
            .unwrap();
        db.insert_telemetry_event("10.0.0.3", "Invalid SSH user", "block", "agent-a", None)
            .await
            .unwrap();

        let profile = db.compute_shared_risk_profile(600).await.unwrap();
        let category = profile
            .categories
            .iter()
            .find(|row| row.category == "Invalid SSH user")
            .expect("campaign category should exist");

        assert_eq!(category.label, "shared:campaign");
        assert_eq!(category.force_threshold, Some(1));
        assert!(profile.global_risk_score > 0.0);
    }

    #[tokio::test]
    async fn shared_risk_profile_exposes_cross_agent_surge() {
        let db = Db::new(":memory:").await.expect("Failed to create test DB");

        for idx in 0..5 {
            let agent = if idx % 2 == 0 { "agent-a" } else { "agent-b" };
            let ip = if idx % 2 == 0 {
                "192.0.2.10"
            } else {
                "192.0.2.20"
            }
            .to_string();
            db.insert_telemetry_event(&ip, "Web SQL Injection attempt", "alert", agent, None)
                .await
                .unwrap();
        }

        let profile = db.compute_shared_risk_profile(600).await.unwrap();
        let category = profile
            .categories
            .iter()
            .find(|row| row.category == "Web SQL Injection attempt")
            .expect("surge category should exist");

        assert_eq!(category.label, "shared:surge");
        assert_eq!(category.force_threshold, None);
    }

    #[tokio::test]
    async fn lookup_ip_activity_combines_local_and_community_history() {
        let db = Db::new(":memory:").await.expect("Failed to create test DB");

        let alpha_id = db
            .insert_agent("agent-alpha", "token-a", None)
            .await
            .unwrap();
        let beta_id = db
            .insert_agent("agent-beta", "token-b", None)
            .await
            .unwrap();
        db.update_agent_nickname(alpha_id, "Tokyo edge")
            .await
            .unwrap();

        db.insert_telemetry_event_with_timestamp(
            "203.0.113.44",
            "SSH repeated connection close",
            "alert",
            "agent-alpha",
            Some("/var/log/auth.log"),
            Some("2026-03-11T09:05:00+00:00"),
        )
        .await
        .unwrap();
        db.insert_telemetry_event_with_timestamp(
            "203.0.113.44",
            "Web SQL Injection attempt",
            "block",
            "agent-beta",
            Some("/var/log/nginx/access.log"),
            Some("2026-03-11T09:10:00+00:00"),
        )
        .await
        .unwrap();

        db.insert_decision_with_timestamp(
            "203.0.113.44",
            "SSH repeated connection close",
            "block",
            "agent-alpha",
            Some("2026-03-11T09:06:00+00:00"),
        )
        .await
        .unwrap()
        .expect("agent decision should be inserted");
        db.insert_decision_with_timestamp(
            "203.0.113.44",
            "Campaign auto-block: SSH brute force",
            "block",
            "campaign",
            Some("2026-03-11T09:12:00+00:00"),
        )
        .await
        .unwrap()
        .expect("campaign decision should be inserted");

        db.insert_decision_with_timestamp(
            "203.0.113.0/24",
            "firehol_level1",
            "block",
            "firehol_level1",
            Some("2026-03-11T08:00:00+00:00"),
        )
        .await
        .unwrap()
        .expect("community cidr decision should be inserted");
        db.insert_decision_with_timestamp(
            "203.0.113.44",
            "ipsum_feed",
            "block",
            "ipsum_feed",
            Some("2026-03-11T08:30:00+00:00"),
        )
        .await
        .unwrap()
        .expect("community exact decision should be inserted");
        db.insert_decision_with_timestamp(
            "198.51.100.0/24",
            "unrelated_feed",
            "block",
            "unrelated_feed",
            Some("2026-03-11T08:40:00+00:00"),
        )
        .await
        .unwrap()
        .expect("unrelated community decision should be inserted");

        let lookup = db.lookup_ip_activity("203.0.113.44", 50).await.unwrap();

        assert_eq!(lookup.ip, "203.0.113.44");
        assert_eq!(lookup.local_history.len(), 2);
        assert_eq!(lookup.local_history[0].source, "agent-beta");
        assert_eq!(lookup.local_history[0].source_label, "agent-beta");
        assert_eq!(lookup.local_history[1].source_label, "Tokyo edge");

        assert_eq!(lookup.machine_summaries.len(), 2);
        assert_eq!(lookup.machine_summaries[0].agent_id, Some(beta_id));
        assert_eq!(lookup.machine_summaries[0].block_count, 1);
        assert_eq!(lookup.machine_summaries[1].source_label, "Tokyo edge");
        assert_eq!(lookup.machine_summaries[1].alert_count, 1);

        assert_eq!(lookup.decision_history.len(), 2);
        assert_eq!(lookup.decision_history[0].source, "campaign");
        assert_eq!(
            lookup.decision_history[0].source_label,
            "Campaign auto-block"
        );
        assert_eq!(lookup.decision_history[1].source, "agent-alpha");

        assert_eq!(lookup.community_matches.len(), 2);
        assert!(lookup
            .community_matches
            .iter()
            .any(|row| row.source == "ipsum_feed" && row.matched_entry == "203.0.113.44"));
        assert!(lookup
            .community_matches
            .iter()
            .any(|row| row.source == "firehol_level1" && row.matched_entry == "203.0.113.0/24"));
    }

    #[tokio::test]
    async fn whitelist_skips_new_decisions() {
        let db = Db::new(":memory:").await.expect("Failed to create test DB");

        db.upsert_whitelist_entry("203.0.113.44", Some("trusted admin"))
            .await
            .unwrap();

        let inserted = db
            .insert_decision("203.0.113.44", "Test reason", "block", "agent")
            .await
            .unwrap();
        assert_eq!(inserted, None);
        assert!(db.list_decisions(10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn cidr_whitelist_skips_covered_exact_decisions() {
        let db = Db::new(":memory:").await.expect("Failed to create test DB");

        db.upsert_whitelist_entry("203.0.113.44/24", Some("office"))
            .await
            .unwrap();

        let inserted = db
            .insert_decision("203.0.113.88", "Test reason", "block", "agent")
            .await
            .unwrap();
        assert_eq!(inserted, None);
    }

    #[tokio::test]
    async fn whitelist_insert_removes_existing_decisions_for_same_ip() {
        let db = Db::new(":memory:").await.expect("Failed to create test DB");

        db.insert_decision("198.51.100.70", "Block me", "block", "agent")
            .await
            .unwrap()
            .expect("decision should be inserted");
        db.insert_decision("198.51.100.71", "Keep me", "block", "agent")
            .await
            .unwrap()
            .expect("decision should be inserted");

        let entry = db
            .upsert_whitelist_entry("198.51.100.70", Some("admin override"))
            .await
            .unwrap();
        assert_eq!(entry.ip, "198.51.100.70");

        let decisions = db.list_decisions(10).await.unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].ip, "198.51.100.71");
    }

    #[tokio::test]
    async fn cidr_whitelist_removes_covered_exact_and_narrower_decisions_only() {
        let db = Db::new(":memory:").await.expect("Failed to create test DB");

        db.insert_decision("203.0.113.44", "Block host", "block", "agent")
            .await
            .unwrap()
            .expect("host decision should be inserted");
        db.insert_decision("203.0.113.0/25", "Block subnet", "block", "feed")
            .await
            .unwrap()
            .expect("narrow subnet should be inserted");
        db.insert_decision("203.0.113.0/24", "Keep broader subnet", "block", "feed")
            .await
            .unwrap()
            .expect("broader subnet should be inserted");

        let entry = db
            .upsert_whitelist_entry("203.0.113.99/25", Some("office half"))
            .await
            .unwrap();
        assert_eq!(entry.ip, "203.0.113.0/25");

        let decisions = db.list_decisions(10).await.unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].ip, "203.0.113.0/24");
    }

    #[tokio::test]
    async fn exact_ip_whitelist_does_not_remove_broader_cidr_decision() {
        let db = Db::new(":memory:").await.expect("Failed to create test DB");

        db.insert_decision("203.0.113.0/24", "Keep subnet", "block", "feed")
            .await
            .unwrap()
            .expect("subnet decision should be inserted");

        db.upsert_whitelist_entry("203.0.113.44", Some("single host"))
            .await
            .unwrap();

        let decisions = db.list_decisions(10).await.unwrap();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].ip, "203.0.113.0/24");
    }

    #[tokio::test]
    async fn behavior_events_round_trip_structured_payloads() {
        let db = Db::new(":memory:").await.expect("Failed to create test DB");

        let id = db
            .insert_behavior_event(&NewBehaviorEvent {
                agent_name: "agent-a".to_string(),
                source: "ebpf_ringbuf".to_string(),
                watched_root: "/srv/data".to_string(),
                pid: Some(42),
                process_name: Some("python3".to_string()),
                exe_path: Some("/usr/bin/python3".to_string()),
                command_line: Some("python3 encrypt.py".to_string()),
                correlation_hits: 4,
                file_ops: BehaviorFileOpsRow {
                    created: 1,
                    modified: 2,
                    renamed: 3,
                    deleted: 4,
                },
                touched_paths: vec!["/srv/data/a.txt".to_string()],
                protected_paths_touched: vec!["/srv/data/secret.txt".to_string()],
                bytes_written: 8192,
                io_rate_bytes_per_sec: 4096,
                score: 67,
                reasons: vec!["rename burst".to_string(), "protected path".to_string()],
                level: "throttle_candidate".to_string(),
                timestamp: Some("2026-03-14T09:00:00+00:00".to_string()),
            })
            .await
            .unwrap();
        assert!(id > 0);

        let rows = db.list_behavior_events(10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].agent_name, "agent-a");
        assert_eq!(rows[0].file_ops.renamed, 3);
        assert_eq!(rows[0].protected_paths_touched.len(), 1);
        assert_eq!(rows[0].level, "throttle_candidate");

        let agent_rows = db
            .list_behavior_events_by_agent("agent-a", 10)
            .await
            .unwrap();
        assert_eq!(agent_rows, rows);
    }

    #[tokio::test]
    async fn containment_events_update_latest_status_and_keep_history() {
        let db = Db::new(":memory:").await.expect("Failed to create test DB");

        db.record_containment_event(&NewContainmentEvent {
            agent_name: "agent-a".to_string(),
            state: "suspicious".to_string(),
            previous_state: Some("normal".to_string()),
            reason: "suspicious score threshold crossed".to_string(),
            watched_root: "/srv/data".to_string(),
            pid: Some(42),
            score: 35,
            actions: Vec::new(),
            outcomes: Vec::new(),
            timestamp: Some("2026-03-14T09:00:00+00:00".to_string()),
        })
        .await
        .unwrap();

        db.record_containment_event(&NewContainmentEvent {
            agent_name: "agent-a".to_string(),
            state: "throttle".to_string(),
            previous_state: Some("suspicious".to_string()),
            reason: "throttle score threshold crossed".to_string(),
            watched_root: "/srv/data".to_string(),
            pid: Some(42),
            score: 65,
            actions: vec!["ApplyIoThrottle".to_string()],
            outcomes: vec![ContainmentOutcomeRow {
                enforcer: "cgroup".to_string(),
                applied: false,
                dry_run: true,
                detail: "dry-run".to_string(),
            }],
            timestamp: Some("2026-03-14T09:01:00+00:00".to_string()),
        })
        .await
        .unwrap();

        let statuses = db.list_containment_statuses(10).await.unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].agent_name, "agent-a");
        assert_eq!(statuses[0].state, "throttle");
        assert_eq!(statuses[0].actions, vec!["ApplyIoThrottle"]);
        assert_eq!(statuses[0].outcomes[0].enforcer, "cgroup");

        let history = db
            .list_containment_events_by_agent("agent-a", 10)
            .await
            .unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].state, "throttle");
        assert_eq!(history[1].state, "suspicious");
    }
}
