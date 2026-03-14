use super::*;

impl Db {
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

    pub async fn get_agent_with_last_seen(
        &self,
        id: i64,
    ) -> anyhow::Result<Option<AgentStatusRow>> {
        let row = sqlx::query_as::<
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
            WHERE a.id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(&self.0)
        .await?;

        Ok(row.map(
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
        ))
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

    pub async fn upsert_agent_heartbeat(
        &self,
        agent_name: &str,
        butterfly_shield_enabled: Option<bool>,
    ) -> anyhow::Result<()> {
        let now = Utc::now().to_rfc3339();
        let flag: Option<i64> = butterfly_shield_enabled.map(|value| value as i64);
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
