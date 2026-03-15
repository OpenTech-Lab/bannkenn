use crate::geoip;
use crate::ip_pattern::{canonicalize_ip_pattern, pattern_covers_pattern};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};
use sqlx::{Row, Sqlite, Transaction};
use std::str::FromStr;
use std::time::Duration;

mod agents;
mod behavior;
mod commands;
mod community;
mod containment;
mod events;
mod helpers;
mod incidents;
mod schema;
mod types;
mod whitelist;

use helpers::*;
pub(crate) use incidents::{AdminAlertInsert, IncidentTimelineInsert};
pub use types::*;

const SQLITE_POOL_MAX_CONNECTIONS: u32 = 4;
const SQLITE_POOL_MIN_CONNECTIONS: u32 = 1;
const SQLITE_WAL_AUTOCHECKPOINT_PAGES: i64 = 2_048;
const SQLITE_JOURNAL_SIZE_LIMIT_BYTES: i64 = 64 * 1024 * 1024;
const SQLITE_WAL_TRUNCATE_THRESHOLD_PAGES: i64 = 16_384;

#[derive(Debug, Clone)]
pub struct Db(SqlitePool);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqliteCheckpointStats {
    pub busy: i64,
    pub log_frames: i64,
    pub checkpointed_frames: i64,
}

impl Db {
    pub async fn new(path: &str) -> anyhow::Result<Self> {
        let opts = SqliteConnectOptions::from_str(&format!("sqlite:{}", path))?
            .create_if_missing(true)
            .busy_timeout(Duration::from_secs(30))
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .pragma(
                "wal_autocheckpoint",
                SQLITE_WAL_AUTOCHECKPOINT_PAGES.to_string(),
            )
            .pragma(
                "journal_size_limit",
                SQLITE_JOURNAL_SIZE_LIMIT_BYTES.to_string(),
            )
            .optimize_on_close(true, 400);
        let pool = SqlitePoolOptions::new()
            .max_connections(SQLITE_POOL_MAX_CONNECTIONS)
            .min_connections(SQLITE_POOL_MIN_CONNECTIONS)
            .acquire_timeout(Duration::from_secs(30))
            .connect_with(opts)
            .await?;
        let db = Db(pool);
        db.migrate().await?;
        if path != ":memory:" {
            let _ = db.checkpoint_wal_truncate().await?;
        }
        Ok(db)
    }

    pub async fn migrate(&self) -> anyhow::Result<()> {
        schema::migrate(&self.0).await
    }

    pub async fn maintain_wal(&self) -> anyhow::Result<Option<SqliteCheckpointStats>> {
        let passive = self.checkpoint_wal_passive().await?;
        if passive.busy == 0 && passive.log_frames >= SQLITE_WAL_TRUNCATE_THRESHOLD_PAGES {
            let truncated = self.checkpoint_wal_truncate().await?;
            return Ok(Some(truncated));
        }

        Ok(None)
    }

    pub async fn checkpoint_wal_passive(&self) -> anyhow::Result<SqliteCheckpointStats> {
        self.checkpoint_wal("PASSIVE").await
    }

    pub async fn checkpoint_wal_truncate(&self) -> anyhow::Result<SqliteCheckpointStats> {
        self.checkpoint_wal("TRUNCATE").await
    }

    async fn checkpoint_wal(&self, mode: &str) -> anyhow::Result<SqliteCheckpointStats> {
        let statement = format!("PRAGMA wal_checkpoint({mode})");
        let (busy, log_frames, checkpointed_frames) =
            sqlx::query_as::<_, (i64, i64, i64)>(&statement)
                .fetch_one(&self.0)
                .await?;

        Ok(SqliteCheckpointStats {
            busy,
            log_frames,
            checkpointed_frames,
        })
    }
}
