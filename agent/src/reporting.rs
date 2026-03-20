use crate::containment::ContainmentDecision;
use crate::ebpf::events::{
    BehaviorEvent, ContainerMount, FileOperationCounts, OrchestratorMetadata, ProcessAncestor,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BehaviorEventUpload {
    pub timestamp: String,
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
    #[serde(default)]
    pub orchestrator: OrchestratorMetadata,
    #[serde(default)]
    pub container_mounts: Vec<ContainerMount>,
    pub correlation_hits: u32,
    pub file_ops: FileOperationCounts,
    pub touched_paths: Vec<String>,
    pub protected_paths_touched: Vec<String>,
    pub bytes_written: u64,
    pub io_rate_bytes_per_sec: u64,
    pub score: u32,
    pub reasons: Vec<String>,
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainmentOutcomeUpload {
    pub enforcer: String,
    pub applied: bool,
    pub dry_run: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainmentStatusUpload {
    pub timestamp: String,
    pub state: String,
    pub previous_state: Option<String>,
    pub reason: String,
    pub watched_root: String,
    pub pid: Option<u32>,
    pub score: u32,
    pub actions: Vec<String>,
    pub outcomes: Vec<ContainmentOutcomeUpload>,
}

impl From<&BehaviorEvent> for BehaviorEventUpload {
    fn from(event: &BehaviorEvent) -> Self {
        Self {
            timestamp: event.timestamp.to_rfc3339(),
            source: event.source.clone(),
            watched_root: event.watched_root.clone(),
            pid: event.pid,
            parent_pid: event.parent_pid,
            uid: event.uid,
            gid: event.gid,
            service_unit: event.service_unit.clone(),
            first_seen_at: event.first_seen_at.map(|timestamp| timestamp.to_rfc3339()),
            trust_class: event.trust_class.map(|class| class.as_str().to_string()),
            trust_policy_name: event.trust_policy_name.clone(),
            maintenance_activity: event
                .maintenance_activity
                .map(|activity| activity.as_str().to_string()),
            package_name: event.package_name.clone(),
            package_manager: event.package_manager.clone(),
            process_name: event.process_name.clone(),
            exe_path: event.exe_path.clone(),
            command_line: event.command_line.clone(),
            parent_process_name: event.parent_process_name.clone(),
            parent_command_line: event.parent_command_line.clone(),
            parent_chain: event.parent_chain.clone(),
            container_runtime: event.container_runtime.clone(),
            container_id: event.container_id.clone(),
            container_image: event.container_image.clone(),
            orchestrator: event.orchestrator.clone(),
            container_mounts: event.container_mounts.clone(),
            correlation_hits: event.correlation_hits,
            file_ops: event.file_ops,
            touched_paths: event.touched_paths.clone(),
            protected_paths_touched: event.protected_paths_touched.clone(),
            bytes_written: event.bytes_written,
            io_rate_bytes_per_sec: event.io_rate_bytes_per_sec,
            score: event.score,
            reasons: event.reasons.clone(),
            level: event.level.as_str().to_string(),
        }
    }
}

impl ContainmentStatusUpload {
    pub fn from_decision(decision: &ContainmentDecision) -> Option<Self> {
        let transition = decision.transition.as_ref()?;
        Some(Self {
            timestamp: transition.at.to_rfc3339(),
            state: decision.state.as_str().to_string(),
            previous_state: Some(transition.from.as_str().to_string()),
            reason: transition.reason.clone(),
            watched_root: transition.watched_root.clone(),
            pid: transition.pid,
            score: transition.score,
            actions: decision
                .actions
                .iter()
                .map(|action| format!("{:?}", action))
                .collect(),
            outcomes: decision
                .outcomes
                .iter()
                .map(|outcome| ContainmentOutcomeUpload {
                    enforcer: outcome.enforcer.clone(),
                    applied: outcome.applied,
                    dry_run: outcome.dry_run,
                    detail: outcome.detail.clone(),
                })
                .collect(),
        })
    }
}
