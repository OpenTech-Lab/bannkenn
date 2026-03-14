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
    process_name TEXT,
    exe_path TEXT,
    command_line TEXT,
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
    pub process_name: Option<String>,
    pub exe_path: Option<String>,
    pub command_line: Option<String>,
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
            process_name: event.process_name.clone(),
            exe_path: event.exe_path.clone(),
            command_line: event.command_line.clone(),
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
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
                $15, $16, $17, $18, $19, $20, $21, $22
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
        .bind(&record.process_name)
        .bind(&record.exe_path)
        .bind(&record.command_line)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{BehaviorFileOpsRow, NewBehaviorEvent};

    #[test]
    fn archive_bootstrap_defines_expected_indexes() {
        assert!(CREATE_BEHAVIOR_ARCHIVE_SQL.contains("behavior_events_archive"));
        assert!(BEHAVIOR_ARCHIVE_INDEXES
            .iter()
            .any(|statement| statement.contains("agent_name, created_at DESC")));
        assert!(BEHAVIOR_ARCHIVE_INDEXES
            .iter()
            .any(|statement| statement.contains("level, created_at DESC")));
        assert!(BEHAVIOR_ARCHIVE_INDEXES
            .iter()
            .any(|statement| statement.contains("watched_root, created_at DESC")));
    }

    #[test]
    fn archive_record_preserves_ingested_behavior_fields() {
        let event = NewBehaviorEvent {
            agent_name: "agent-a".to_string(),
            source: "ebpf_ringbuf".to_string(),
            watched_root: "/srv/data".to_string(),
            pid: Some(42),
            process_name: Some("python3".to_string()),
            exe_path: Some("/usr/bin/python3".to_string()),
            command_line: Some("python3 encrypt.py".to_string()),
            correlation_hits: 3,
            file_ops: BehaviorFileOpsRow {
                created: 1,
                modified: 2,
                renamed: 4,
                deleted: 1,
            },
            touched_paths: vec!["/srv/data/a.txt".to_string()],
            protected_paths_touched: vec!["/srv/data/secret.txt".to_string()],
            bytes_written: 16384,
            io_rate_bytes_per_sec: 4096,
            score: 88,
            reasons: vec!["rename burst x4".to_string()],
            level: "fuse_candidate".to_string(),
            timestamp: Some("2026-03-14T09:00:00+00:00".to_string()),
        };

        let record =
            BehaviorArchiveRecord::from_ingested_event(17, 5, &event, "2026-03-14T09:00:00+00:00")
                .unwrap();

        assert_eq!(record.sqlite_event_id, 17);
        assert_eq!(record.incident_id, 5);
        assert_eq!(record.file_ops_renamed, 4);
        assert_eq!(record.level, "fuse_candidate");
        assert!(record.reasons_json.contains("rename burst x4"));
    }
}
