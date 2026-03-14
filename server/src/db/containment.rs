use super::*;

impl Db {
    pub async fn record_containment_event(
        &self,
        event: &NewContainmentEvent,
    ) -> anyhow::Result<i64> {
        let created_at = normalize_event_timestamp(event.timestamp.as_deref());
        let mut tx = self.0.begin().await?;
        let cutoff = incident_cutoff(&created_at);

        let mut incident = if let Some(existing) = Self::find_recent_incident_for_agent_root(
            &mut tx,
            &event.agent_name,
            &event.watched_root,
            &cutoff,
        )
        .await?
        {
            existing
        } else {
            Self::create_incident(
                &mut tx,
                &build_containment_incident_key(event),
                build_containment_incident_title(&event.agent_name, &event.state),
                build_containment_incident_summary(event),
                event.reason.clone(),
                containment_state_to_severity(&event.state),
                &created_at,
            )
            .await?
        };

        let event_id =
            Self::insert_containment_event_row(&mut tx, event, &created_at, Some(incident.id))
                .await?;

        let actions_json = encode_json(&event.actions)?;
        let outcomes_json = encode_json(&event.outcomes)?;
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
        .bind(&actions_json)
        .bind(&outcomes_json)
        .bind(&created_at)
        .execute(&mut *tx)
        .await?;

        Self::insert_incident_timeline(
            &mut tx,
            incident.id,
            "containment_event",
            Some(event_id),
            &event.agent_name,
            &event.watched_root,
            containment_state_to_severity(&event.state),
            &build_containment_alert_message(event),
            &json!({
                "state": &event.state,
                "previous_state": &event.previous_state,
                "reason": &event.reason,
                "pid": event.pid,
                "score": event.score,
                "actions": &event.actions,
                "outcomes": &event.outcomes,
            }),
            &created_at,
        )
        .await?;

        push_unique_sorted(&mut incident.affected_agents, &event.agent_name);
        push_unique_sorted(&mut incident.affected_roots, &event.watched_root);
        incident.correlated_agent_count = incident.affected_agents.len() as u32;
        incident.cross_agent = incident.correlated_agent_count > 1;
        incident.event_count += 1;
        incident.latest_state = Some(event.state.clone());
        incident.latest_score = event.score;
        incident.last_seen_at = created_at.clone();
        incident.severity = max_severity(
            &incident.severity,
            containment_state_to_severity(&event.state),
        )
        .to_string();

        if incident.incident_key.starts_with("containment:") {
            incident.primary_reason = event.reason.clone();
            incident.title = build_containment_incident_title(&event.agent_name, &event.state);
            incident.summary = build_containment_incident_summary(event);
        } else {
            incident.title =
                build_behavior_incident_title(&incident.primary_reason, incident.cross_agent);
            incident.summary = format!(
                "{}; containment moved to {} on {}",
                build_behavior_incident_summary(
                    &incident.primary_reason,
                    incident.affected_agents.len(),
                    &incident.affected_roots,
                    &event.watched_root,
                ),
                event.state,
                event.agent_name
            );
        }

        let alert_title = build_containment_alert_title(&event.agent_name, &event.state);
        let alert_message = build_containment_alert_message(event);
        Self::insert_admin_alert(
            &mut tx,
            "containment_transition",
            containment_state_to_severity(&event.state),
            &alert_title,
            &alert_message,
            Some(&event.agent_name),
            Some(incident.id),
            &json!({
                "state": &event.state,
                "previous_state": &event.previous_state,
                "reason": &event.reason,
                "watched_root": &event.watched_root,
                "score": event.score,
                "actions": &event.actions,
                "outcomes": &event.outcomes,
            }),
            &created_at,
        )
        .await?;
        incident.alert_count += 1;

        Self::update_incident(&mut tx, &incident).await?;
        tx.commit().await?;

        Ok(event_id)
    }

    pub(crate) async fn insert_containment_event_row(
        tx: &mut Transaction<'_, Sqlite>,
        event: &NewContainmentEvent,
        created_at: &str,
        incident_id: Option<i64>,
    ) -> anyhow::Result<i64> {
        let actions_json = encode_json(&event.actions)?;
        let outcomes_json = encode_json(&event.outcomes)?;
        let result = sqlx::query(
            r#"
            INSERT INTO containment_events (
                incident_id,
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(incident_id)
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
        .execute(&mut **tx)
        .await?;

        Ok(result.last_insert_rowid())
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

        rows.into_iter().map(map_containment_status_row).collect()
    }

    pub async fn list_containment_events(
        &self,
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
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            "#,
        )
        .bind(limit)
        .fetch_all(&self.0)
        .await?;

        rows.into_iter().map(map_containment_event_row).collect()
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

        rows.into_iter().map(map_containment_event_row).collect()
    }
}

fn map_containment_status_row(
    (
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
    ): (
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
) -> anyhow::Result<ContainmentStatusRow> {
    Ok(ContainmentStatusRow {
        agent_name,
        state,
        previous_state,
        reason,
        watched_root,
        pid: from_i64_opt_u32(pid, "agent_containment_status.pid")?,
        score: from_i64_u32(score, "agent_containment_status.score")?,
        actions: decode_json(&actions_json, "agent_containment_status.actions_json")?,
        outcomes: decode_json(&outcomes_json, "agent_containment_status.outcomes_json")?,
        updated_at,
    })
}

fn map_containment_event_row(
    (
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
    ): (
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
) -> anyhow::Result<ContainmentEventRow> {
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
}
