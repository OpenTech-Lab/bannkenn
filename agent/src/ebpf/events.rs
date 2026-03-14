use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileOperationCounts {
    #[serde(default)]
    pub created: u32,
    #[serde(default)]
    pub modified: u32,
    #[serde(default)]
    pub renamed: u32,
    #[serde(default)]
    pub deleted: u32,
}

impl FileOperationCounts {
    pub fn is_empty(&self) -> bool {
        self.created == 0 && self.modified == 0 && self.renamed == 0 && self.deleted == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileActivityBatch {
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub watched_root: String,
    pub poll_interval_ms: u64,
    pub file_ops: FileOperationCounts,
    pub touched_paths: Vec<String>,
    pub protected_paths_touched: Vec<String>,
    pub bytes_written: u64,
    pub io_rate_bytes_per_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub process_name: String,
    pub exe_path: String,
    pub command_line: String,
    pub correlation_hits: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorLevel {
    Observed,
    Suspicious,
    ThrottleCandidate,
    FuseCandidate,
}

impl BehaviorLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Suspicious => "suspicious",
            Self::ThrottleCandidate => "throttle_candidate",
            Self::FuseCandidate => "fuse_candidate",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BehaviorEvent {
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub watched_root: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub exe_path: Option<String>,
    pub command_line: Option<String>,
    pub correlation_hits: u32,
    pub file_ops: FileOperationCounts,
    pub touched_paths: Vec<String>,
    pub protected_paths_touched: Vec<String>,
    pub bytes_written: u64,
    pub io_rate_bytes_per_sec: u64,
    pub score: u32,
    pub reasons: Vec<String>,
    pub level: BehaviorLevel,
}
