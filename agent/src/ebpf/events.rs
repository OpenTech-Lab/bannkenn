use crate::config::TrustPolicyVisibility;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::mem::size_of;

pub const RAW_BEHAVIOR_PATH_CAPACITY: usize = 256;
pub const RAW_BEHAVIOR_PROCESS_CAPACITY: usize = 128;
pub const RAW_BEHAVIOR_EVENT_KIND_FILE_ACTIVITY: u32 = 0;
pub const RAW_BEHAVIOR_EVENT_KIND_PROCESS_EXEC: u32 = 1;
pub const RAW_BEHAVIOR_EVENT_KIND_PROCESS_EXIT: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawBehaviorEventKind {
    FileActivity,
    ProcessExec,
    ProcessExit,
    Unknown(u32),
}

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
    #[serde(default)]
    pub rename_extension_targets: Vec<String>,
    pub bytes_written: u64,
    pub io_rate_bytes_per_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    #[serde(default)]
    pub parent_pid: Option<u32>,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub gid: Option<u32>,
    #[serde(default)]
    pub service_unit: Option<String>,
    pub first_seen_at: DateTime<Utc>,
    #[serde(default)]
    pub trust_class: ProcessTrustClass,
    #[serde(default)]
    pub trust_policy_name: Option<String>,
    #[serde(default)]
    pub maintenance_activity: Option<MaintenanceActivity>,
    #[serde(skip, default)]
    pub trust_policy_visibility: TrustPolicyVisibility,
    #[serde(default)]
    pub package_name: Option<String>,
    #[serde(default)]
    pub package_manager: Option<String>,
    pub process_name: String,
    pub exe_path: String,
    pub command_line: String,
    pub correlation_hits: u32,
    #[serde(default)]
    pub parent_process_name: Option<String>,
    #[serde(default)]
    pub parent_command_line: Option<String>,
    #[serde(default)]
    pub parent_chain: Vec<ProcessAncestor>,
    #[serde(default)]
    pub container_runtime: Option<String>,
    #[serde(default)]
    pub container_id: Option<String>,
    #[serde(default)]
    pub container_image: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessAncestor {
    pub pid: u32,
    #[serde(default)]
    pub process_name: Option<String>,
    #[serde(default)]
    pub exe_path: Option<String>,
    #[serde(default)]
    pub command_line: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProcessTrustClass {
    #[serde(rename = "trusted_system_process")]
    TrustedSystem,
    #[serde(rename = "trusted_package_managed_process")]
    TrustedPackageManaged,
    #[serde(rename = "allowed_local_process")]
    AllowedLocal,
    #[serde(rename = "unknown_process")]
    #[default]
    Unknown,
    #[serde(rename = "suspicious_process")]
    Suspicious,
}

impl ProcessTrustClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TrustedSystem => "trusted_system_process",
            Self::TrustedPackageManaged => "trusted_package_managed_process",
            Self::AllowedLocal => "allowed_local_process",
            Self::Unknown => "unknown_process",
            Self::Suspicious => "suspicious_process",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MaintenanceActivity {
    #[serde(rename = "package_manager_helper")]
    PackageManagerHelper,
    #[serde(rename = "trusted_maintenance")]
    TrustedMaintenance,
}

impl MaintenanceActivity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PackageManagerHelper => "package_manager_helper",
            Self::TrustedMaintenance => "trusted_maintenance",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorLevel {
    Observed,
    Suspicious,
    HighRisk,
    ContainmentCandidate,
}

impl BehaviorLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Suspicious => "suspicious",
            Self::HighRisk => "high_risk",
            Self::ContainmentCandidate => "containment_candidate",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BehaviorEvent {
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub watched_root: String,
    pub pid: Option<u32>,
    pub parent_pid: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub service_unit: Option<String>,
    pub first_seen_at: Option<DateTime<Utc>>,
    pub trust_class: Option<ProcessTrustClass>,
    pub trust_policy_name: Option<String>,
    pub maintenance_activity: Option<MaintenanceActivity>,
    #[serde(skip, default)]
    pub trust_policy_visibility: TrustPolicyVisibility,
    pub package_name: Option<String>,
    pub package_manager: Option<String>,
    pub process_name: Option<String>,
    pub exe_path: Option<String>,
    pub command_line: Option<String>,
    pub parent_process_name: Option<String>,
    pub parent_command_line: Option<String>,
    #[serde(default)]
    pub parent_chain: Vec<ProcessAncestor>,
    pub container_runtime: Option<String>,
    pub container_id: Option<String>,
    #[serde(default)]
    pub container_image: Option<String>,
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawBehaviorRingEvent {
    pub pid: u32,
    pub event_kind: u32,
    pub bytes_written: u64,
    pub created: u32,
    pub modified: u32,
    pub renamed: u32,
    pub deleted: u32,
    pub protected_path_touched: u32,
    pub path_len: u32,
    pub process_name_len: u32,
    pub path: [u8; RAW_BEHAVIOR_PATH_CAPACITY],
    pub process_name: [u8; RAW_BEHAVIOR_PROCESS_CAPACITY],
}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for RawBehaviorRingEvent {}

impl RawBehaviorRingEvent {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < size_of::<Self>() {
            return None;
        }

        let mut event = Self {
            pid: 0,
            event_kind: RAW_BEHAVIOR_EVENT_KIND_FILE_ACTIVITY,
            bytes_written: 0,
            created: 0,
            modified: 0,
            renamed: 0,
            deleted: 0,
            protected_path_touched: 0,
            path_len: 0,
            process_name_len: 0,
            path: [0; RAW_BEHAVIOR_PATH_CAPACITY],
            process_name: [0; RAW_BEHAVIOR_PROCESS_CAPACITY],
        };
        // The ring buffer payload is emitted by a fixed-size C-compatible struct.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                &mut event as *mut Self as *mut u8,
                size_of::<Self>(),
            );
        }
        Some(event)
    }

    pub fn path_string(&self) -> String {
        let len = usize::try_from(self.path_len)
            .ok()
            .map(|len| len.min(self.path.len()))
            .unwrap_or(0);
        String::from_utf8_lossy(&self.path[..len]).into_owned()
    }

    pub fn process_name_string(&self) -> String {
        let len = usize::try_from(self.process_name_len)
            .ok()
            .map(|len| len.min(self.process_name.len()))
            .unwrap_or(0);
        String::from_utf8_lossy(&self.process_name[..len]).into_owned()
    }

    pub fn event_kind(&self) -> RawBehaviorEventKind {
        match self.event_kind {
            RAW_BEHAVIOR_EVENT_KIND_FILE_ACTIVITY => RawBehaviorEventKind::FileActivity,
            RAW_BEHAVIOR_EVENT_KIND_PROCESS_EXEC => RawBehaviorEventKind::ProcessExec,
            RAW_BEHAVIOR_EVENT_KIND_PROCESS_EXIT => RawBehaviorEventKind::ProcessExit,
            other => RawBehaviorEventKind::Unknown(other),
        }
    }

    pub fn is_lifecycle_event(&self) -> bool {
        matches!(
            self.event_kind(),
            RawBehaviorEventKind::ProcessExec | RawBehaviorEventKind::ProcessExit
        )
    }

    pub fn file_ops(&self) -> FileOperationCounts {
        FileOperationCounts {
            created: self.created,
            modified: self.modified,
            renamed: self.renamed,
            deleted: self.deleted,
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/ebpf/events_tests.rs"]
mod tests;
