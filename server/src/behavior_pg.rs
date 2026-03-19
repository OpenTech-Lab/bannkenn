use crate::db::NewBehaviorEvent;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;

const CREATE_BEHAVIOR_ARCHIVE_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS behavior_events_archive (
    id BIGSERIAL PRIMARY KEY,
    sqlite_event_id BIGINT NOT NULL UNIQUE,
    incident_id BIGINT NOT NULL,
    agent_name TEXT NOT NULL,
    source TEXT NOT NULL,
    watched_root TEXT NOT NULL,
    pid INTEGER,
    parent_pid INTEGER,
    uid INTEGER,
    gid INTEGER,
    service_unit TEXT,
    first_seen_at TIMESTAMPTZ,
    trust_class TEXT,
    trust_policy_name TEXT,
    maintenance_activity TEXT,
    package_name TEXT,
    package_manager TEXT,
    parent_chain_json TEXT NOT NULL DEFAULT '[]',
    process_name TEXT,
    exe_path TEXT,
    command_line TEXT,
    parent_process_name TEXT,
    parent_command_line TEXT,
    container_runtime TEXT,
    container_id TEXT,
    correlation_hits BIGINT NOT NULL,
    file_ops_created BIGINT NOT NULL,
    file_ops_modified BIGINT NOT NULL,
    file_ops_renamed BIGINT NOT NULL,
    file_ops_deleted BIGINT NOT NULL,
    touched_paths_json TEXT NOT NULL,
    protected_paths_json TEXT NOT NULL,
    bytes_written BIGINT NOT NULL,
    io_rate_bytes_per_sec BIGINT NOT NULL,
    score BIGINT NOT NULL,
    reasons_json TEXT NOT NULL,
    level TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
)
"#;

const BEHAVIOR_ARCHIVE_INDEXES: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS idx_behavior_events_archive_created_at ON behavior_events_archive(created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_behavior_events_archive_agent_created_at ON behavior_events_archive(agent_name, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_behavior_events_archive_level_created_at ON behavior_events_archive(level, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_behavior_events_archive_root_created_at ON behavior_events_archive(watched_root, created_at DESC)",
];

#[doc(hidden)]
pub fn archive_schema_sql() -> &'static str {
    CREATE_BEHAVIOR_ARCHIVE_SQL
}

#[doc(hidden)]
pub fn archive_index_statements() -> &'static [&'static str] {
    BEHAVIOR_ARCHIVE_INDEXES
}

#[derive(Debug, Clone)]
pub struct BehaviorPgArchive {
    pool: PgPool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BehaviorArchiveRecord {
    pub sqlite_event_id: i64,
    pub incident_id: i64,
    pub agent_name: String,
    pub source: String,
    pub watched_root: String,
    pub pid: Option<u32>,
    pub parent_pid: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub service_unit: Option<String>,
    pub first_seen_at: Option<String>,
    pub trust_class: Option<String>,
    pub trust_policy_name: Option<String>,
    pub maintenance_activity: Option<String>,
    pub package_name: Option<String>,
    pub package_manager: Option<String>,
    pub parent_chain_json: String,
    pub process_name: Option<String>,
    pub exe_path: Option<String>,
    pub command_line: Option<String>,
    pub parent_process_name: Option<String>,
    pub parent_command_line: Option<String>,
    pub container_runtime: Option<String>,
    pub container_id: Option<String>,
    pub correlation_hits: u32,
    pub file_ops_created: u32,
    pub file_ops_modified: u32,
    pub file_ops_renamed: u32,
    pub file_ops_deleted: u32,
    pub touched_paths_json: String,
    pub protected_paths_json: String,
    pub bytes_written: u64,
    pub io_rate_bytes_per_sec: u64,
    pub score: u32,
    pub reasons_json: String,
    pub level: String,
    pub created_at: String,
}

impl BehaviorArchiveRecord {
    pub fn from_ingested_event(
        sqlite_event_id: i64,
        incident_id: i64,
        event: &NewBehaviorEvent,
        created_at: &str,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            sqlite_event_id,
            incident_id,
            agent_name: event.agent_name.clone(),
            source: event.source.clone(),
            watched_root: event.watched_root.clone(),
            pid: event.pid,
            parent_pid: event.parent_pid,
            uid: event.uid,
            gid: event.gid,
            service_unit: event.service_unit.clone(),
            first_seen_at: event.first_seen_at.clone(),
            trust_class: event.trust_class.clone(),
            trust_policy_name: event.trust_policy_name.clone(),
            maintenance_activity: event.maintenance_activity.clone(),
            package_name: event.package_name.clone(),
            package_manager: event.package_manager.clone(),
            parent_chain_json: serde_json::to_string(&event.parent_chain)?,
            process_name: event.process_name.clone(),
            exe_path: event.exe_path.clone(),
            command_line: event.command_line.clone(),
            parent_process_name: event.parent_process_name.clone(),
            parent_command_line: event.parent_command_line.clone(),
            container_runtime: event.container_runtime.clone(),
            container_id: event.container_id.clone(),
            correlation_hits: event.correlation_hits,
            file_ops_created: event.file_ops.created,
            file_ops_modified: event.file_ops.modified,
            file_ops_renamed: event.file_ops.renamed,
            file_ops_deleted: event.file_ops.deleted,
            touched_paths_json: serde_json::to_string(&event.touched_paths)?,
            protected_paths_json: serde_json::to_string(&event.protected_paths_touched)?,
            bytes_written: event.bytes_written,
            io_rate_bytes_per_sec: event.io_rate_bytes_per_sec,
            score: event.score,
            reasons_json: serde_json::to_string(&event.reasons)?,
            level: event.level.clone(),
            created_at: created_at.to_string(),
        })
    }
}

impl BehaviorPgArchive {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(Duration::from_secs(5))
            .connect(database_url)
            .await
            .with_context(|| "failed to connect optional behavior PostgreSQL archive")?;

        let archive = Self { pool };
        archive.bootstrap().await?;
        Ok(archive)
    }

    async fn bootstrap(&self) -> anyhow::Result<()> {
        sqlx::query(CREATE_BEHAVIOR_ARCHIVE_SQL)
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "ALTER TABLE behavior_events_archive ADD COLUMN IF NOT EXISTS parent_process_name TEXT",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE behavior_events_archive ADD COLUMN IF NOT EXISTS parent_command_line TEXT",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE behavior_events_archive ADD COLUMN IF NOT EXISTS parent_pid INTEGER",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("ALTER TABLE behavior_events_archive ADD COLUMN IF NOT EXISTS uid INTEGER")
            .execute(&self.pool)
            .await?;
        sqlx::query("ALTER TABLE behavior_events_archive ADD COLUMN IF NOT EXISTS gid INTEGER")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "ALTER TABLE behavior_events_archive ADD COLUMN IF NOT EXISTS service_unit TEXT",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE behavior_events_archive ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMPTZ",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE behavior_events_archive ADD COLUMN IF NOT EXISTS trust_class TEXT",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE behavior_events_archive ADD COLUMN IF NOT EXISTS trust_policy_name TEXT",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE behavior_events_archive ADD COLUMN IF NOT EXISTS maintenance_activity TEXT",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE behavior_events_archive ADD COLUMN IF NOT EXISTS package_name TEXT",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE behavior_events_archive ADD COLUMN IF NOT EXISTS package_manager TEXT",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE behavior_events_archive ADD COLUMN IF NOT EXISTS parent_chain_json TEXT NOT NULL DEFAULT '[]'",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE behavior_events_archive ADD COLUMN IF NOT EXISTS container_runtime TEXT",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "ALTER TABLE behavior_events_archive ADD COLUMN IF NOT EXISTS container_id TEXT",
        )
        .execute(&self.pool)
        .await?;
        for statement in BEHAVIOR_ARCHIVE_INDEXES {
            sqlx::query(statement).execute(&self.pool).await?;
        }
        Ok(())
    }

    pub async fn archive_event(&self, record: &BehaviorArchiveRecord) -> anyhow::Result<()> {
        sqlx::query(
            r#"
            INSERT INTO behavior_events_archive (
                sqlite_event_id,
                incident_id,
                agent_name,
                source,
                watched_root,
                pid,
                parent_pid,
                uid,
                gid,
                service_unit,
                first_seen_at,
                trust_class,
                trust_policy_name,
                maintenance_activity,
                package_name,
                package_manager,
                parent_chain_json,
                process_name,
                exe_path,
                command_line,
                parent_process_name,
                parent_command_line,
                container_runtime,
                container_id,
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
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26,
                $27, $28, $29, $30, $31, $32, $33, $34, $35, $36
            )
            ON CONFLICT (sqlite_event_id) DO NOTHING
            "#,
        )
        .bind(record.sqlite_event_id)
        .bind(record.incident_id)
        .bind(&record.agent_name)
        .bind(&record.source)
        .bind(&record.watched_root)
        .bind(record.pid.map(|value| value as i32))
        .bind(record.parent_pid.map(|value| value as i32))
        .bind(record.uid.map(|value| value as i32))
        .bind(record.gid.map(|value| value as i32))
        .bind(&record.service_unit)
        .bind(&record.first_seen_at)
        .bind(&record.trust_class)
        .bind(&record.trust_policy_name)
        .bind(&record.maintenance_activity)
        .bind(&record.package_name)
        .bind(&record.package_manager)
        .bind(&record.parent_chain_json)
        .bind(&record.process_name)
        .bind(&record.exe_path)
        .bind(&record.command_line)
        .bind(&record.parent_process_name)
        .bind(&record.parent_command_line)
        .bind(&record.container_runtime)
        .bind(&record.container_id)
        .bind(i64::from(record.correlation_hits))
        .bind(i64::from(record.file_ops_created))
        .bind(i64::from(record.file_ops_modified))
        .bind(i64::from(record.file_ops_renamed))
        .bind(i64::from(record.file_ops_deleted))
        .bind(&record.touched_paths_json)
        .bind(&record.protected_paths_json)
        .bind(i64::try_from(record.bytes_written).context("bytes_written out of range")?)
        .bind(
            i64::try_from(record.io_rate_bytes_per_sec)
                .context("io_rate_bytes_per_sec out of range")?,
        )
        .bind(i64::from(record.score))
        .bind(&record.reasons_json)
        .bind(&record.level)
        .bind(&record.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
