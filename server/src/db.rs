use crate::geoip;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool};
use std::str::FromStr;
use std::time::Duration;

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
pub struct CommunityIpRow {
    pub ip: String,
    pub source: String,
    pub sightings: i64,
    pub last_seen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityFeedRow {
    pub source: String,
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
            CREATE INDEX IF NOT EXISTS idx_telemetry_source_created_at ON telemetry_events(source, created_at DESC)
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

        Ok(())
    }

    pub async fn insert_decision(
        &self,
        ip: &str,
        reason: &str,
        action: &str,
        source: &str,
    ) -> anyhow::Result<i64> {
        let created_at = Utc::now().to_rfc3339();
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

        Ok(result.last_insert_rowid())
    }

    pub async fn insert_telemetry_event(
        &self,
        ip: &str,
        reason: &str,
        level: &str,
        source: &str,
        log_path: Option<&str>,
    ) -> anyhow::Result<i64> {
        let created_at = Utc::now().to_rfc3339();
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

    pub async fn list_decisions(&self, limit: i64) -> anyhow::Result<Vec<DecisionRow>> {
        let rows = sqlx::query_as::<_, (i64, String, String, String, String, Option<String>, Option<String>, String, Option<String>)>(
            "SELECT id, ip, reason, action, source, country, asn_org, created_at, expires_at FROM decisions ORDER BY id DESC LIMIT ?",
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
            "SELECT id, ip, reason, action, source, country, asn_org, created_at, expires_at FROM decisions WHERE source = ? ORDER BY id DESC LIMIT ?",
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
            "SELECT id, ip, reason, level, source, log_path, country, asn_org, created_at FROM telemetry_events WHERE source = ? ORDER BY id DESC LIMIT ?",
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
            "SELECT id, ip, reason, level, source, log_path, country, asn_org, created_at FROM telemetry_events ORDER BY id DESC LIMIT ?",
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
        let rows = sqlx::query_as::<_, (String, String, i64, String)>(
            r#"
            SELECT
                ip,
                source,
                COUNT(*) as sightings,
                MAX(created_at) as last_seen_at
            FROM decisions
            WHERE source != 'agent'
            GROUP BY ip, source
            ORDER BY last_seen_at DESC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(ip, source, sightings, last_seen_at)| CommunityIpRow {
                ip,
                source,
                sightings,
                last_seen_at,
            })
            .collect())
    }

    pub async fn list_community_feeds(&self) -> anyhow::Result<Vec<CommunityFeedRow>> {
        let rows = sqlx::query_as::<_, (String, i64, String, String)>(
            r#"
            SELECT
                source,
                COUNT(DISTINCT ip) as ip_count,
                MIN(created_at) as first_seen_at,
                MAX(created_at) as last_seen_at
            FROM decisions
            WHERE source != 'agent'
            GROUP BY source
            ORDER BY last_seen_at DESC
            "#,
        )
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(source, ip_count, first_seen_at, last_seen_at)| CommunityFeedRow {
                    source,
                    ip_count,
                    first_seen_at,
                    last_seen_at,
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
                ip,
                MAX(reason) as reason,
                COUNT(*) as sightings,
                MIN(created_at) as first_seen_at,
                MAX(created_at) as last_seen_at
            FROM decisions
            WHERE source = ?
            GROUP BY ip
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
            WHERE created_at > datetime('now', '-' || ? || ' seconds')
              AND level IN ('alert', 'block')
            "#,
        )
        .bind(window_secs)
        .fetch_all(&self.0)
        .await?;

        // Normalise reason → category (strip count annotations like "(2/5)" or "(threshold: 5)").
        fn categorize(reason: &str) -> &str {
            if let Some(idx) = reason.rfind(" (") {
                let suffix = &reason[idx + 2..];
                if suffix.ends_with(')') {
                    return &reason[..idx];
                }
            }
            reason
        }

        // Build: category → (set of IPs, set of agent sources).
        use std::collections::{HashMap, HashSet};
        let mut cat_ips: HashMap<String, HashSet<String>> = HashMap::new();
        let mut cat_agents: HashMap<String, HashSet<String>> = HashMap::new();
        // Also track IP → category for result building.
        let mut ip_categories: HashMap<String, String> = HashMap::new();

        for (ip, reason, source) in &rows {
            let cat = categorize(reason).to_string();
            cat_ips.entry(cat.clone()).or_default().insert(ip.clone());
            cat_agents.entry(cat.clone()).or_default().insert(source.clone());
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
        let already_blocked: HashSet<String> = sqlx::query_as::<_, (String,)>(
            "SELECT DISTINCT ip FROM decisions",
        )
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
            .insert_decision("192.168.1.1", "Test reason 1", "block", "agent")
            .await
            .expect("Failed to insert decision 1");
        assert!(id1 > 0);

        let id2 = db
            .insert_decision("192.168.1.2", "Test reason 2", "block", "agent")
            .await
            .expect("Failed to insert decision 2");
        assert!(id2 > id1);

        // List decisions
        let decisions = db
            .list_decisions(100)
            .await
            .expect("Failed to list decisions");

        assert_eq!(decisions.len(), 2);
        assert_eq!(decisions[0].ip, "192.168.1.2"); // Newest first due to ORDER BY DESC
        assert_eq!(decisions[1].ip, "192.168.1.1");
        assert_eq!(decisions[0].reason, "Test reason 2");
        assert_eq!(decisions[1].reason, "Test reason 1");
    }
}
