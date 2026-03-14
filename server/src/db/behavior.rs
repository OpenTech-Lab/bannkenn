use super::*;

impl Db {
    pub async fn insert_behavior_event(&self, event: &NewBehaviorEvent) -> anyhow::Result<i64> {
        let created_at = normalize_event_timestamp(event.timestamp.as_deref());
        let mut tx = self.0.begin().await?;
        let id = Self::insert_behavior_event_row(&mut tx, event, &created_at, None).await?;
        tx.commit().await?;
        Ok(id)
    }

    pub async fn ingest_behavior_event(
        &self,
        event: &NewBehaviorEvent,
    ) -> anyhow::Result<BehaviorIngestResult> {
        let created_at = normalize_event_timestamp(event.timestamp.as_deref());
        let incident_key = build_behavior_incident_key(event);
        let primary_reason = primary_behavior_reason(&event.reasons);
        let mut tx = self.0.begin().await?;
        let cutoff = incident_cutoff(&created_at);

        let mut incident = if let Some(existing) =
            Self::find_recent_incident_by_key(&mut tx, &incident_key, &cutoff).await?
        {
            existing
        } else {
            Self::create_incident(
                &mut tx,
                &incident_key,
                build_behavior_incident_title(&primary_reason, false),
                build_behavior_incident_summary(
                    &primary_reason,
                    1,
                    &[event.watched_root.clone()],
                    &event.watched_root,
                ),
                primary_reason.clone(),
                behavior_level_to_severity(&event.level),
                &created_at,
            )
            .await?
        };

        let event_id =
            Self::insert_behavior_event_row(&mut tx, event, &created_at, Some(incident.id)).await?;

        Self::insert_incident_timeline(
            &mut tx,
            incident.id,
            "behavior_event",
            Some(event_id),
            &event.agent_name,
            &event.watched_root,
            behavior_level_to_severity(&event.level),
            &format!("{} observed on {}", primary_reason, event.watched_root),
            &json!({
                "source": &event.source,
                "level": &event.level,
                "pid": event.pid,
                "process_name": &event.process_name,
                "exe_path": &event.exe_path,
                "command_line": &event.command_line,
                "correlation_hits": event.correlation_hits,
                "file_ops": &event.file_ops,
                "touched_paths": &event.touched_paths,
                "protected_paths_touched": &event.protected_paths_touched,
                "bytes_written": event.bytes_written,
                "io_rate_bytes_per_sec": event.io_rate_bytes_per_sec,
                "score": event.score,
                "reasons": &event.reasons,
            }),
            &created_at,
        )
        .await?;

        push_unique_sorted(&mut incident.affected_agents, &event.agent_name);
        push_unique_sorted(&mut incident.affected_roots, &event.watched_root);
        incident.correlated_agent_count = incident.affected_agents.len() as u32;
        incident.cross_agent = incident.correlated_agent_count > 1;
        incident.event_count += 1;
        incident.latest_score = event.score;
        incident.last_seen_at = created_at.clone();
        incident.severity =
            max_severity(&incident.severity, behavior_level_to_severity(&event.level)).to_string();
        incident.title =
            build_behavior_incident_title(&incident.primary_reason, incident.cross_agent);
        incident.summary = build_behavior_incident_summary(
            &incident.primary_reason,
            incident.affected_agents.len(),
            &incident.affected_roots,
            &event.watched_root,
        );

        if incident.cross_agent && !incident.cross_agent_alerted {
            let watched_root = incident
                .affected_roots
                .first()
                .cloned()
                .unwrap_or_else(|| event.watched_root.clone());
            let title = build_cross_agent_alert_title(&incident.primary_reason);
            let message = build_cross_agent_alert_message(
                &incident.primary_reason,
                &incident.affected_agents,
                &watched_root,
            );
            Self::insert_admin_alert(
                &mut tx,
                "cross_agent_incident",
                "high",
                &title,
                &message,
                None,
                Some(incident.id),
                &json!({
                    "incident_key": &incident.incident_key,
                    "primary_reason": &incident.primary_reason,
                    "affected_agents": &incident.affected_agents,
                    "affected_roots": &incident.affected_roots,
                    "event_count": incident.event_count,
                }),
                &created_at,
            )
            .await?;
            incident.cross_agent_alerted = true;
            incident.alert_count += 1;
        }

        Self::update_incident(&mut tx, &incident).await?;
        tx.commit().await?;

        Ok(BehaviorIngestResult {
            id: event_id,
            incident_id: incident.id,
            created_at,
        })
    }

    pub(crate) async fn insert_behavior_event_row(
        tx: &mut Transaction<'_, Sqlite>,
        event: &NewBehaviorEvent,
        created_at: &str,
        incident_id: Option<i64>,
    ) -> anyhow::Result<i64> {
        let touched_paths_json = encode_json(&event.touched_paths)?;
        let protected_paths_json = encode_json(&event.protected_paths_touched)?;
        let reasons_json = encode_json(&event.reasons)?;
        let result = sqlx::query(
            r#"
            INSERT INTO behavior_events (
                incident_id,
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(incident_id)
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
        .execute(&mut **tx)
        .await?;

        Ok(result.last_insert_rowid())
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

        rows.into_iter().map(map_behavior_event_row).collect()
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

        rows.into_iter().map(map_behavior_event_row).collect()
    }
}

fn map_behavior_event_row(row: sqlx::sqlite::SqliteRow) -> anyhow::Result<BehaviorEventRow> {
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
        touched_paths: decode_json(&touched_paths_json, "behavior_events.touched_paths_json")?,
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
}
