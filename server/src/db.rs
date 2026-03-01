use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct Db(SqlitePool);

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
        let opts =
            SqliteConnectOptions::from_str(&format!("sqlite:{}", path))?.create_if_missing(true);
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
                created_at TEXT NOT NULL,
                expires_at TEXT
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
        let result = sqlx::query(
            r#"
            INSERT INTO decisions (ip, reason, action, source, created_at)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(ip)
        .bind(reason)
        .bind(action)
        .bind(source)
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
            sqlx::query_as::<_, (i64, String, String, String, String, String, Option<String>)>(
                "SELECT id, ip, reason, action, source, created_at, expires_at FROM decisions \
             WHERE id > ? ORDER BY id ASC LIMIT ?",
            )
            .bind(since_id)
            .bind(limit)
            .fetch_all(&self.0)
            .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, ip, reason, action, source, created_at, expires_at)| DecisionRow {
                    id,
                    ip,
                    reason,
                    action,
                    source,
                    created_at,
                    expires_at,
                },
            )
            .collect())
    }

    pub async fn list_decisions(&self, limit: i64) -> anyhow::Result<Vec<DecisionRow>> {
        let rows = sqlx::query_as::<_, (i64, String, String, String, String, String, Option<String>)>(
            "SELECT id, ip, reason, action, source, created_at, expires_at FROM decisions ORDER BY id DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, ip, reason, action, source, created_at, expires_at)| DecisionRow {
                    id,
                    ip,
                    reason,
                    action,
                    source,
                    created_at,
                    expires_at,
                },
            )
            .collect())
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
            ),
        >(
            r#"
            SELECT
                a.id,
                a.name,
                a.uuid,
                a.nickname,
                a.created_at,
                h.last_heartbeat_at as last_seen_at
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
                |(id, name, uuid, nickname, created_at, last_seen_at)| AgentStatusRow {
                    id,
                    name,
                    uuid,
                    nickname,
                    created_at,
                    last_seen_at,
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

    pub async fn upsert_agent_heartbeat(&self, agent_name: &str) -> anyhow::Result<()> {
        let now = Utc::now().to_rfc3339();
        sqlx::query(
            r#"
            INSERT INTO agent_heartbeats (agent_name, last_heartbeat_at)
            VALUES (?, ?)
            ON CONFLICT(agent_name) DO UPDATE SET
                last_heartbeat_at = excluded.last_heartbeat_at
            "#,
        )
        .bind(agent_name)
        .bind(now)
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
