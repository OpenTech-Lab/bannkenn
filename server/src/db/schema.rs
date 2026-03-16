use super::*;

pub(crate) async fn migrate(pool: &SqlitePool) -> anyhow::Result<()> {
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
    .execute(pool)
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
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS behavior_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER,
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
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS containment_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER,
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
    .execute(pool)
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
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS containment_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_name TEXT NOT NULL,
            command_kind TEXT NOT NULL,
            reason TEXT NOT NULL,
            watched_root TEXT,
            pid INTEGER,
            requested_by TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            resulting_state TEXT,
            result_message TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            executed_at TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_key TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            primary_reason TEXT NOT NULL,
            latest_state TEXT,
            latest_score INTEGER NOT NULL DEFAULT 0,
            event_count INTEGER NOT NULL DEFAULT 0,
            correlated_agent_count INTEGER NOT NULL DEFAULT 0,
            affected_agents_json TEXT NOT NULL DEFAULT '[]',
            affected_roots_json TEXT NOT NULL DEFAULT '[]',
            cross_agent INTEGER NOT NULL DEFAULT 0,
            cross_agent_alerted INTEGER NOT NULL DEFAULT 0,
            alert_count INTEGER NOT NULL DEFAULT 0,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS incident_timeline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            source_type TEXT NOT NULL,
            source_event_id INTEGER,
            agent_name TEXT NOT NULL,
            watched_root TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            payload_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS admin_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            agent_name TEXT,
            incident_id INTEGER,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
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
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_decisions_ip ON decisions(ip)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_decisions_created_at ON decisions(created_at DESC)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_decisions_source_created_at ON decisions(source, created_at DESC)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_telemetry_source_created_at ON telemetry_events(source, created_at DESC)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_telemetry_created_at ON telemetry_events(created_at DESC)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_telemetry_ip_source_created_at ON telemetry_events(ip, source, created_at DESC)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_behavior_events_created_at ON behavior_events(created_at DESC)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_behavior_events_agent_created_at ON behavior_events(agent_name, created_at DESC)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_behavior_events_level_created_at ON behavior_events(level, created_at DESC)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_behavior_events_incident_created_at
            ON behavior_events(incident_id, created_at DESC)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_containment_events_created_at ON containment_events(created_at DESC)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_containment_events_agent_created_at ON containment_events(agent_name, created_at DESC)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_containment_events_incident_created_at
            ON containment_events(incident_id, created_at DESC)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_agent_containment_status_updated_at ON agent_containment_status(updated_at DESC)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_containment_actions_agent_status_created_at
            ON containment_actions(agent_name, status, created_at ASC)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_containment_actions_updated_at
            ON containment_actions(updated_at DESC)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_incidents_last_seen_at ON incidents(last_seen_at DESC)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_incidents_key_last_seen
            ON incidents(incident_key, last_seen_at DESC)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_incident_timeline_incident_created_at
            ON incident_timeline(incident_id, created_at ASC)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE INDEX IF NOT EXISTS idx_admin_alerts_created_at
            ON admin_alerts(created_at DESC)
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS agent_heartbeats (
            agent_name TEXT PRIMARY KEY,
            last_heartbeat_at TEXT NOT NULL
        )
        "#,
    )
    .execute(pool)
    .await?;

    let _ = sqlx::query("ALTER TABLE agents ADD COLUMN uuid TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE agents ADD COLUMN nickname TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE decisions ADD COLUMN country TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE decisions ADD COLUMN asn_org TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE behavior_events ADD COLUMN incident_id INTEGER")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE containment_events ADD COLUMN incident_id INTEGER")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE agent_heartbeats ADD COLUMN butterfly_shield_enabled INTEGER")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE agent_heartbeats ADD COLUMN containment_sensor TEXT")
        .execute(pool)
        .await;

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
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_ssh_logins_created_at ON ssh_logins(created_at DESC)",
    )
    .execute(pool)
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
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_whitelist_entries_created_at ON whitelist_entries(created_at DESC)",
    )
    .execute(pool)
    .await?;

    Ok(())
}
