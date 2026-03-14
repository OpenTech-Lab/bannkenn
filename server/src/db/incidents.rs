use super::*;

#[derive(Debug, Clone)]
pub(crate) struct IncidentState {
    pub(crate) id: i64,
    pub(crate) incident_key: String,
    pub(crate) status: String,
    pub(crate) severity: String,
    pub(crate) title: String,
    pub(crate) summary: String,
    pub(crate) primary_reason: String,
    pub(crate) latest_state: Option<String>,
    pub(crate) latest_score: u32,
    pub(crate) event_count: u32,
    pub(crate) correlated_agent_count: u32,
    pub(crate) affected_agents: Vec<String>,
    pub(crate) affected_roots: Vec<String>,
    pub(crate) cross_agent: bool,
    pub(crate) cross_agent_alerted: bool,
    pub(crate) first_seen_at: String,
    pub(crate) last_seen_at: String,
    pub(crate) alert_count: u32,
}

impl Db {
    pub(crate) async fn create_incident(
        tx: &mut Transaction<'_, Sqlite>,
        incident_key: &str,
        title: String,
        summary: String,
        primary_reason: String,
        severity: &str,
        created_at: &str,
    ) -> anyhow::Result<IncidentState> {
        let empty_list = encode_json(&Vec::<String>::new())?;
        let result = sqlx::query(
            r#"
            INSERT INTO incidents (
                incident_key,
                status,
                severity,
                title,
                summary,
                primary_reason,
                latest_state,
                latest_score,
                event_count,
                correlated_agent_count,
                affected_agents_json,
                affected_roots_json,
                cross_agent,
                cross_agent_alerted,
                alert_count,
                first_seen_at,
                last_seen_at
            )
            VALUES (?, 'open', ?, ?, ?, ?, NULL, 0, 0, 0, ?, ?, 0, 0, 0, ?, ?)
            "#,
        )
        .bind(incident_key)
        .bind(severity)
        .bind(&title)
        .bind(&summary)
        .bind(&primary_reason)
        .bind(&empty_list)
        .bind(&empty_list)
        .bind(created_at)
        .bind(created_at)
        .execute(&mut **tx)
        .await?;

        Ok(IncidentState {
            id: result.last_insert_rowid(),
            incident_key: incident_key.to_string(),
            status: "open".to_string(),
            severity: severity.to_string(),
            title,
            summary,
            primary_reason,
            latest_state: None,
            latest_score: 0,
            event_count: 0,
            correlated_agent_count: 0,
            affected_agents: Vec::new(),
            affected_roots: Vec::new(),
            cross_agent: false,
            cross_agent_alerted: false,
            first_seen_at: created_at.to_string(),
            last_seen_at: created_at.to_string(),
            alert_count: 0,
        })
    }

    pub(crate) async fn find_recent_incident_by_key(
        tx: &mut Transaction<'_, Sqlite>,
        incident_key: &str,
        cutoff: &str,
    ) -> anyhow::Result<Option<IncidentState>> {
        let row = sqlx::query(
            r#"
            SELECT
                id,
                incident_key,
                status,
                severity,
                title,
                summary,
                primary_reason,
                latest_state,
                latest_score,
                event_count,
                correlated_agent_count,
                affected_agents_json,
                affected_roots_json,
                cross_agent,
                cross_agent_alerted,
                first_seen_at,
                last_seen_at,
                alert_count
            FROM incidents
            WHERE incident_key = ?
              AND status = 'open'
              AND last_seen_at >= ?
            ORDER BY last_seen_at DESC, id DESC
            LIMIT 1
            "#,
        )
        .bind(incident_key)
        .bind(cutoff)
        .fetch_optional(&mut **tx)
        .await?;

        row.map(Self::map_incident_state).transpose()
    }

    pub(crate) async fn find_recent_incident_for_agent_root(
        tx: &mut Transaction<'_, Sqlite>,
        agent_name: &str,
        watched_root: &str,
        cutoff: &str,
    ) -> anyhow::Result<Option<IncidentState>> {
        let behavior_row = sqlx::query(
            r#"
            SELECT
                i.id,
                i.incident_key,
                i.status,
                i.severity,
                i.title,
                i.summary,
                i.primary_reason,
                i.latest_state,
                i.latest_score,
                i.event_count,
                i.correlated_agent_count,
                i.affected_agents_json,
                i.affected_roots_json,
                i.cross_agent,
                i.cross_agent_alerted,
                i.first_seen_at,
                i.last_seen_at,
                i.alert_count
            FROM incidents i
            INNER JOIN behavior_events b ON b.incident_id = i.id
            WHERE b.agent_name = ?
              AND b.watched_root = ?
              AND b.created_at >= ?
            ORDER BY b.created_at DESC, b.id DESC
            LIMIT 1
            "#,
        )
        .bind(agent_name)
        .bind(watched_root)
        .bind(cutoff)
        .fetch_optional(&mut **tx)
        .await?;

        if let Some(row) = behavior_row {
            return Self::map_incident_state(row).map(Some);
        }

        let containment_row = sqlx::query(
            r#"
            SELECT
                i.id,
                i.incident_key,
                i.status,
                i.severity,
                i.title,
                i.summary,
                i.primary_reason,
                i.latest_state,
                i.latest_score,
                i.event_count,
                i.correlated_agent_count,
                i.affected_agents_json,
                i.affected_roots_json,
                i.cross_agent,
                i.cross_agent_alerted,
                i.first_seen_at,
                i.last_seen_at,
                i.alert_count
            FROM incidents i
            INNER JOIN containment_events c ON c.incident_id = i.id
            WHERE c.agent_name = ?
              AND c.watched_root = ?
              AND c.created_at >= ?
            ORDER BY c.created_at DESC, c.id DESC
            LIMIT 1
            "#,
        )
        .bind(agent_name)
        .bind(watched_root)
        .bind(cutoff)
        .fetch_optional(&mut **tx)
        .await?;

        containment_row.map(Self::map_incident_state).transpose()
    }

    pub(crate) fn map_incident_state(
        row: sqlx::sqlite::SqliteRow,
    ) -> anyhow::Result<IncidentState> {
        let affected_agents_json: String = row.try_get("affected_agents_json")?;
        let affected_roots_json: String = row.try_get("affected_roots_json")?;
        Ok(IncidentState {
            id: row.try_get("id")?,
            incident_key: row.try_get("incident_key")?,
            status: row.try_get("status")?,
            severity: row.try_get("severity")?,
            title: row.try_get("title")?,
            summary: row.try_get("summary")?,
            primary_reason: row.try_get("primary_reason")?,
            latest_state: row.try_get("latest_state")?,
            latest_score: from_i64_u32(row.try_get("latest_score")?, "incidents.latest_score")?,
            event_count: from_i64_u32(row.try_get("event_count")?, "incidents.event_count")?,
            correlated_agent_count: from_i64_u32(
                row.try_get("correlated_agent_count")?,
                "incidents.correlated_agent_count",
            )?,
            affected_agents: decode_json(&affected_agents_json, "incidents.affected_agents_json")?,
            affected_roots: decode_json(&affected_roots_json, "incidents.affected_roots_json")?,
            cross_agent: row.try_get::<i64, _>("cross_agent")? != 0,
            cross_agent_alerted: row.try_get::<i64, _>("cross_agent_alerted")? != 0,
            first_seen_at: row.try_get("first_seen_at")?,
            last_seen_at: row.try_get("last_seen_at")?,
            alert_count: from_i64_u32(row.try_get("alert_count")?, "incidents.alert_count")?,
        })
    }

    pub(crate) fn incident_row_from_state(incident: IncidentState) -> IncidentRow {
        IncidentRow {
            id: incident.id,
            incident_key: incident.incident_key,
            status: incident.status,
            severity: incident.severity,
            title: incident.title,
            summary: incident.summary,
            primary_reason: incident.primary_reason,
            latest_state: incident.latest_state,
            latest_score: incident.latest_score,
            event_count: incident.event_count,
            correlated_agent_count: incident.correlated_agent_count,
            affected_agents: incident.affected_agents,
            affected_roots: incident.affected_roots,
            cross_agent: incident.cross_agent,
            first_seen_at: incident.first_seen_at,
            last_seen_at: incident.last_seen_at,
            alert_count: incident.alert_count,
        }
    }

    pub(crate) async fn update_incident(
        tx: &mut Transaction<'_, Sqlite>,
        incident: &IncidentState,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            UPDATE incidents
            SET
                status = ?,
                severity = ?,
                title = ?,
                summary = ?,
                primary_reason = ?,
                latest_state = ?,
                latest_score = ?,
                event_count = ?,
                correlated_agent_count = ?,
                affected_agents_json = ?,
                affected_roots_json = ?,
                cross_agent = ?,
                cross_agent_alerted = ?,
                last_seen_at = ?,
                alert_count = ?
            WHERE id = ?
            "#,
        )
        .bind(&incident.status)
        .bind(&incident.severity)
        .bind(&incident.title)
        .bind(&incident.summary)
        .bind(&incident.primary_reason)
        .bind(&incident.latest_state)
        .bind(i64::from(incident.latest_score))
        .bind(i64::from(incident.event_count))
        .bind(i64::from(incident.correlated_agent_count))
        .bind(encode_json(&incident.affected_agents)?)
        .bind(encode_json(&incident.affected_roots)?)
        .bind(if incident.cross_agent { 1_i64 } else { 0_i64 })
        .bind(if incident.cross_agent_alerted {
            1_i64
        } else {
            0_i64
        })
        .bind(&incident.last_seen_at)
        .bind(i64::from(incident.alert_count))
        .bind(incident.id)
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    pub(crate) async fn insert_incident_timeline(
        tx: &mut Transaction<'_, Sqlite>,
        incident_id: i64,
        source_type: &str,
        source_event_id: Option<i64>,
        agent_name: &str,
        watched_root: &str,
        severity: &str,
        message: &str,
        payload: &Value,
        created_at: &str,
    ) -> anyhow::Result<i64> {
        let result = sqlx::query(
            r#"
            INSERT INTO incident_timeline (
                incident_id,
                source_type,
                source_event_id,
                agent_name,
                watched_root,
                severity,
                message,
                payload_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(incident_id)
        .bind(source_type)
        .bind(source_event_id)
        .bind(agent_name)
        .bind(watched_root)
        .bind(severity)
        .bind(message)
        .bind(encode_json(payload)?)
        .bind(created_at)
        .execute(&mut **tx)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub(crate) async fn insert_admin_alert(
        tx: &mut Transaction<'_, Sqlite>,
        alert_type: &str,
        severity: &str,
        title: &str,
        message: &str,
        agent_name: Option<&str>,
        incident_id: Option<i64>,
        metadata: &Value,
        created_at: &str,
    ) -> anyhow::Result<i64> {
        let result = sqlx::query(
            r#"
            INSERT INTO admin_alerts (
                alert_type,
                severity,
                title,
                message,
                agent_name,
                incident_id,
                metadata_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(alert_type)
        .bind(severity)
        .bind(title)
        .bind(message)
        .bind(agent_name)
        .bind(incident_id)
        .bind(encode_json(metadata)?)
        .bind(created_at)
        .execute(&mut **tx)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn list_incidents(&self, limit: i64) -> anyhow::Result<Vec<IncidentRow>> {
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                incident_key,
                status,
                severity,
                title,
                summary,
                primary_reason,
                latest_state,
                latest_score,
                event_count,
                correlated_agent_count,
                affected_agents_json,
                affected_roots_json,
                cross_agent,
                cross_agent_alerted,
                first_seen_at,
                last_seen_at,
                alert_count
            FROM incidents
            ORDER BY last_seen_at DESC, id DESC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        rows.into_iter()
            .map(Self::map_incident_state)
            .map(|result| result.map(Self::incident_row_from_state))
            .collect()
    }

    pub async fn get_incident_detail(
        &self,
        id: i64,
        timeline_limit: i64,
    ) -> anyhow::Result<Option<IncidentDetailRow>> {
        let incident_row = sqlx::query(
            r#"
            SELECT
                id,
                incident_key,
                status,
                severity,
                title,
                summary,
                primary_reason,
                latest_state,
                latest_score,
                event_count,
                correlated_agent_count,
                affected_agents_json,
                affected_roots_json,
                cross_agent,
                cross_agent_alerted,
                first_seen_at,
                last_seen_at,
                alert_count
            FROM incidents
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(&self.0)
        .await?;

        let Some(incident_row) = incident_row else {
            return Ok(None);
        };

        let timeline_rows = sqlx::query(
            r#"
            SELECT
                id,
                source_type,
                source_event_id,
                agent_name,
                watched_root,
                severity,
                message,
                payload_json,
                created_at
            FROM incident_timeline
            WHERE incident_id = ?
            ORDER BY created_at ASC, id ASC
            LIMIT ?
            "#,
        )
        .bind(id)
        .bind(timeline_limit)
        .fetch_all(&self.0)
        .await?;

        let timeline = timeline_rows
            .into_iter()
            .map(|row| {
                let payload_json: String = row.try_get("payload_json")?;
                Ok(IncidentTimelineRow {
                    id: row.try_get("id")?,
                    source_type: row.try_get("source_type")?,
                    source_event_id: row.try_get("source_event_id")?,
                    agent_name: row.try_get("agent_name")?,
                    watched_root: row.try_get("watched_root")?,
                    severity: row.try_get("severity")?,
                    message: row.try_get("message")?,
                    payload: decode_json(&payload_json, "incident_timeline.payload_json")?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(Some(IncidentDetailRow {
            incident: Self::incident_row_from_state(Self::map_incident_state(incident_row)?),
            timeline,
        }))
    }

    pub async fn list_admin_alerts(&self, limit: i64) -> anyhow::Result<Vec<AdminAlertRow>> {
        let rows = sqlx::query(
            r#"
            SELECT
                id,
                alert_type,
                severity,
                title,
                message,
                agent_name,
                incident_id,
                metadata_json,
                created_at
            FROM admin_alerts
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        rows.into_iter()
            .map(|row| {
                let metadata_json: String = row.try_get("metadata_json")?;
                Ok(AdminAlertRow {
                    id: row.try_get("id")?,
                    alert_type: row.try_get("alert_type")?,
                    severity: row.try_get("severity")?,
                    title: row.try_get("title")?,
                    message: row.try_get("message")?,
                    agent_name: row.try_get("agent_name")?,
                    incident_id: row.try_get("incident_id")?,
                    metadata: decode_json(&metadata_json, "admin_alerts.metadata_json")?,
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect()
    }
}
