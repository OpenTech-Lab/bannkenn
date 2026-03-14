use crate::geoip;
use crate::ip_pattern::{canonicalize_ip_pattern, pattern_covers_pattern};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool};
use sqlx::{Row, Sqlite, Transaction};
use std::str::FromStr;
use std::time::Duration;

mod agents;
mod behavior;
mod community;
mod containment;
mod events;
mod helpers;
mod incidents;
mod schema;
mod types;
mod whitelist;

use helpers::*;
pub use types::*;

#[derive(Debug, Clone)]
pub struct Db(SqlitePool);

impl Db {
    pub async fn new(path: &str) -> anyhow::Result<Self> {
        let opts = SqliteConnectOptions::from_str(&format!("sqlite:{}", path))?
            .create_if_missing(true)
            .busy_timeout(Duration::from_secs(30))
            .journal_mode(SqliteJournalMode::Wal);
        let pool = SqlitePool::connect_with(opts).await?;
        let db = Db(pool);
        db.migrate().await?;
        Ok(db)
    }

    pub async fn migrate(&self) -> anyhow::Result<()> {
        schema::migrate(&self.0).await
    }
}
