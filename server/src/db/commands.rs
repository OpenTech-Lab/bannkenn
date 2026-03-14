use super::*;

impl Db {
    pub async fn create_containment_action(
        &self,
        action: &NewContainmentAction,
    ) -> anyhow::Result<ContainmentActionRow> {
        let now = Utc::now().to_rfc3339();
        let result = sqlx::query(
            r#"
            INSERT INTO containment_actions (
                agent_name,
                command_kind,
                reason,
                watched_root,
                pid,
                requested_by,
                status,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
            "#,
        )
        .bind(&action.agent_name)
        .bind(&action.command_kind)
        .bind(&action.reason)
        .bind(&action.watched_root)
        .bind(action.pid.map(i64::from))
        .bind(&action.requested_by)
        .bind(&now)
        .bind(&now)
        .execute(&self.0)
        .await?;

        let id = result.last_insert_rowid();
        let row = self
            .get_containment_action_by_id_for_agent(id, &action.agent_name)
            .await?;

        row.ok_or_else(|| anyhow::anyhow!("created containment action was not found"))
    }

    pub async fn list_containment_actions_by_agent(
        &self,
        agent_name: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<ContainmentActionRow>> {
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                agent_name,
                command_kind,
                reason,
                watched_root,
                pid,
                requested_by,
                status,
                resulting_state,
                result_message,
                created_at,
                updated_at,
                executed_at
            FROM containment_actions
            WHERE agent_name = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            "#,
        )
        .bind(agent_name)
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        rows.into_iter().map(map_containment_action_row).collect()
    }

    pub async fn list_pending_containment_actions_by_agent(
        &self,
        agent_name: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<ContainmentActionRow>> {
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                agent_name,
                command_kind,
                reason,
                watched_root,
                pid,
                requested_by,
                status,
                resulting_state,
                result_message,
                created_at,
                updated_at,
                executed_at
            FROM containment_actions
            WHERE agent_name = ?
              AND status = 'pending'
            ORDER BY created_at ASC, id ASC
            LIMIT ?
            "#,
        )
        .bind(agent_name)
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        rows.into_iter().map(map_containment_action_row).collect()
    }

    pub async fn complete_containment_action(
        &self,
        action_id: i64,
        agent_name: &str,
        status: &str,
        resulting_state: Option<&str>,
        result_message: Option<&str>,
        executed_at: Option<&str>,
    ) -> anyhow::Result<Option<ContainmentActionRow>> {
        let updated_at = Utc::now().to_rfc3339();
        let executed_at = normalize_event_timestamp(executed_at);
        let result = sqlx::query(
            r#"
            UPDATE containment_actions
            SET
                status = ?,
                resulting_state = ?,
                result_message = ?,
                updated_at = ?,
                executed_at = ?
            WHERE id = ?
              AND agent_name = ?
            "#,
        )
        .bind(status)
        .bind(resulting_state)
        .bind(result_message)
        .bind(&updated_at)
        .bind(&executed_at)
        .bind(action_id)
        .bind(agent_name)
        .execute(&self.0)
        .await?;

        if result.rows_affected() == 0 {
            return Ok(None);
        }

        self.get_containment_action_by_id_for_agent(action_id, agent_name)
            .await
    }

    async fn get_containment_action_by_id_for_agent(
        &self,
        action_id: i64,
        agent_name: &str,
    ) -> anyhow::Result<Option<ContainmentActionRow>> {
        let row = sqlx::query(
            r#"
            SELECT
                id,
                agent_name,
                command_kind,
                reason,
                watched_root,
                pid,
                requested_by,
                status,
                resulting_state,
                result_message,
                created_at,
                updated_at,
                executed_at
            FROM containment_actions
            WHERE id = ?
              AND agent_name = ?
            "#,
        )
        .bind(action_id)
        .bind(agent_name)
        .fetch_optional(&self.0)
        .await?;

        row.map(map_containment_action_row).transpose()
    }
}

fn map_containment_action_row(
    row: sqlx::sqlite::SqliteRow,
) -> anyhow::Result<ContainmentActionRow> {
    Ok(ContainmentActionRow {
        id: row.try_get("id")?,
        agent_name: row.try_get("agent_name")?,
        command_kind: row.try_get("command_kind")?,
        reason: row.try_get("reason")?,
        watched_root: row.try_get("watched_root")?,
        pid: from_i64_opt_u32(row.try_get("pid")?, "containment_actions.pid")?,
        requested_by: row.try_get("requested_by")?,
        status: row.try_get("status")?,
        resulting_state: row.try_get("resulting_state")?,
        result_message: row.try_get("result_message")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        executed_at: row.try_get("executed_at")?,
    })
}
