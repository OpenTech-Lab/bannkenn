use crate::auth::AuthenticatedAgent;
use crate::behavior_pg::{BehaviorArchiveRecord, BehaviorPgArchive};
use crate::db::{
    BehaviorContainerMountRow, BehaviorFileOpsRow, BehaviorOrchestratorRow,
    BehaviorParentChainEntry, Db, NewBehaviorEvent,
};
use crate::validation::{cap_string, cap_vec, MAX_STRING_BYTES, MAX_VEC_ITEMS};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub struct AppState {
    pub db: Arc<Db>,
    pub behavior_archive: Option<Arc<BehaviorPgArchive>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateBehaviorEventRequest {
    pub timestamp: Option<String>,
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
    #[serde(default)]
    pub parent_chain: Vec<BehaviorParentChainEntry>,
    pub process_name: Option<String>,
    pub exe_path: Option<String>,
    pub command_line: Option<String>,
    pub parent_process_name: Option<String>,
    pub parent_command_line: Option<String>,
    pub container_runtime: Option<String>,
    pub container_id: Option<String>,
    pub container_image: Option<String>,
    #[serde(default)]
    pub orchestrator: BehaviorOrchestratorRow,
    #[serde(default)]
    pub container_mounts: Vec<BehaviorContainerMountRow>,
    pub correlation_hits: u32,
    pub file_ops: BehaviorFileOpsRow,
    #[serde(default)]
    pub touched_paths: Vec<String>,
    #[serde(default)]
    pub protected_paths_touched: Vec<String>,
    pub bytes_written: u64,
    pub io_rate_bytes_per_sec: u64,
    pub score: u32,
    #[serde(default)]
    pub reasons: Vec<String>,
    pub level: String,
}

#[derive(Debug, Serialize)]
pub struct CreateBehaviorEventResponse {
    pub id: i64,
}

#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub limit: Option<i64>,
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    agent: AuthenticatedAgent,
    Json(payload): Json<CreateBehaviorEventRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let level = match payload.level.trim().to_lowercase().as_str() {
        "observed" => "observed".to_string(),
        "suspicious" => "suspicious".to_string(),
        "high_risk" | "throttle_candidate" => "high_risk".to_string(),
        "containment_candidate" | "fuse_candidate" => "containment_candidate".to_string(),
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let event = NewBehaviorEvent {
        agent_name: agent.0.clone(),
        source: cap_string(payload.source, MAX_STRING_BYTES),
        watched_root: cap_string(payload.watched_root, MAX_STRING_BYTES),
        pid: payload.pid,
        parent_pid: payload.parent_pid,
        uid: payload.uid,
        gid: payload.gid,
        service_unit: cap_optional_string(payload.service_unit),
        first_seen_at: payload.first_seen_at,
        trust_class: cap_optional_string(payload.trust_class),
        trust_policy_name: cap_optional_string(payload.trust_policy_name),
        maintenance_activity: cap_optional_string(payload.maintenance_activity),
        package_name: cap_optional_string(payload.package_name),
        package_manager: cap_optional_string(payload.package_manager),
        parent_chain: cap_parent_chain(payload.parent_chain),
        process_name: cap_optional_string(payload.process_name),
        exe_path: cap_optional_string(payload.exe_path),
        command_line: cap_optional_string(payload.command_line),
        parent_process_name: cap_optional_string(payload.parent_process_name),
        parent_command_line: cap_optional_string(payload.parent_command_line),
        container_runtime: cap_optional_string(payload.container_runtime),
        container_id: cap_optional_string(payload.container_id),
        container_image: cap_optional_string(payload.container_image),
        orchestrator: cap_orchestrator(payload.orchestrator),
        container_mounts: cap_container_mounts(payload.container_mounts),
        correlation_hits: payload.correlation_hits,
        file_ops: payload.file_ops,
        touched_paths: cap_vec(payload.touched_paths, MAX_VEC_ITEMS),
        protected_paths_touched: cap_vec(payload.protected_paths_touched, MAX_VEC_ITEMS),
        bytes_written: payload.bytes_written,
        io_rate_bytes_per_sec: payload.io_rate_bytes_per_sec,
        score: payload.score,
        reasons: cap_vec(payload.reasons, MAX_VEC_ITEMS),
        level,
        timestamp: payload.timestamp,
    };

    let id = state
        .db
        .ingest_behavior_event(&event)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if let Some(archive) = state.behavior_archive.as_ref() {
        let record = BehaviorArchiveRecord::from_ingested_event(
            id.id,
            id.incident_id,
            &event,
            &id.created_at,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if let Err(err) = archive.archive_event(&record).await {
            tracing::error!(
                "failed to archive behavior event {} to postgres: {}",
                id.id,
                err
            );
        }
    }

    Ok((
        StatusCode::CREATED,
        Json(CreateBehaviorEventResponse { id: id.id }),
    ))
}

fn cap_optional_string(value: Option<String>) -> Option<String> {
    value.map(|value| cap_string(value, MAX_STRING_BYTES))
}

fn cap_parent_chain(parent_chain: Vec<BehaviorParentChainEntry>) -> Vec<BehaviorParentChainEntry> {
    cap_vec(parent_chain, MAX_VEC_ITEMS)
        .into_iter()
        .map(|entry| BehaviorParentChainEntry {
            pid: entry.pid,
            process_name: cap_optional_string(entry.process_name),
            exe_path: cap_optional_string(entry.exe_path),
            command_line: cap_optional_string(entry.command_line),
        })
        .collect()
}

fn cap_orchestrator(orchestrator: BehaviorOrchestratorRow) -> BehaviorOrchestratorRow {
    BehaviorOrchestratorRow {
        platform: cap_optional_string(orchestrator.platform),
        namespace: cap_optional_string(orchestrator.namespace),
        workload: cap_optional_string(orchestrator.workload),
    }
}

fn cap_container_mounts(mounts: Vec<BehaviorContainerMountRow>) -> Vec<BehaviorContainerMountRow> {
    cap_vec(mounts, MAX_VEC_ITEMS)
        .into_iter()
        .map(|mount| BehaviorContainerMountRow {
            mount_type: cap_string(mount.mount_type, MAX_STRING_BYTES),
            source: cap_optional_string(mount.source),
            destination: cap_string(mount.destination, MAX_STRING_BYTES),
            name: cap_optional_string(mount.name),
        })
        .collect()
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let limit = params.limit.unwrap_or(500).clamp(1, 5000);
    let rows = state
        .db
        .list_behavior_events(limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_parent_chain_caps_nested_fields() {
        let oversized = "x".repeat(MAX_STRING_BYTES + 32);
        let capped = cap_parent_chain(vec![BehaviorParentChainEntry {
            pid: 42,
            process_name: Some(oversized.clone()),
            exe_path: Some(oversized.clone()),
            command_line: Some(oversized),
        }]);

        assert_eq!(capped.len(), 1);
        assert_eq!(capped[0].pid, 42);
        assert_eq!(
            capped[0].process_name.as_ref().map(String::len),
            Some(MAX_STRING_BYTES)
        );
        assert_eq!(
            capped[0].exe_path.as_ref().map(String::len),
            Some(MAX_STRING_BYTES)
        );
        assert_eq!(
            capped[0].command_line.as_ref().map(String::len),
            Some(MAX_STRING_BYTES)
        );
    }

    #[test]
    fn cap_parent_chain_keeps_vector_limit() {
        let capped = cap_parent_chain(
            (0..(MAX_VEC_ITEMS + 5))
                .map(|pid| BehaviorParentChainEntry {
                    pid: pid as u32,
                    process_name: Some(format!("proc-{pid}")),
                    exe_path: None,
                    command_line: None,
                })
                .collect(),
        );

        assert_eq!(capped.len(), MAX_VEC_ITEMS);
        assert_eq!(capped[0].pid, 0);
        assert_eq!(capped[MAX_VEC_ITEMS - 1].pid, (MAX_VEC_ITEMS - 1) as u32);
    }
}
