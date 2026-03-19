use crate::ebpf::events::{FileActivityBatch, ProcessInfo};
use crate::ebpf::lifecycle::{LifecycleSnapshot, TrackedProcess};
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CorrelationResult {
    pub process: Option<ProcessInfo>,
    pub protected_hits: u32,
}

#[derive(Debug, Default)]
pub struct ProcessCorrelator;

impl ProcessCorrelator {
    pub fn new() -> Self {
        Self
    }

    pub fn correlate(
        &self,
        batch: &FileActivityBatch,
        snapshot: &LifecycleSnapshot,
    ) -> CorrelationResult {
        let root = Path::new(&batch.watched_root);
        let touched_paths = batch
            .touched_paths
            .iter()
            .map(|path| path.to_string())
            .collect::<HashSet<_>>();

        let mut best_process = None;
        let mut best_hits = 0u32;
        let mut protected_hits = 0u32;

        for proc_info in &snapshot.processes {
            let correlation_hits = count_matching_paths(proc_info, root, &touched_paths);
            if correlation_hits == 0 {
                continue;
            }

            if proc_info.protected {
                protected_hits = protected_hits.max(correlation_hits);
                continue;
            }

            if correlation_hits > best_hits {
                best_hits = correlation_hits;
                best_process = Some(ProcessInfo {
                    pid: proc_info.pid,
                    parent_pid: proc_info.parent_pid,
                    uid: proc_info.uid,
                    gid: proc_info.gid,
                    service_unit: proc_info.service_unit.clone(),
                    first_seen_at: proc_info.first_seen_at,
                    trust_class: proc_info.trust_class,
                    trust_policy_name: proc_info.trust_policy_name.clone(),
                    maintenance_activity: proc_info.maintenance_activity,
                    trust_policy_visibility: proc_info.trust_policy_visibility,
                    package_name: proc_info.package_name.clone(),
                    package_manager: proc_info.package_manager.clone(),
                    process_name: proc_info.process_name.clone(),
                    exe_path: proc_info.exe_path.clone(),
                    command_line: proc_info.command_line.clone(),
                    correlation_hits,
                    parent_process_name: proc_info.parent_process_name.clone(),
                    parent_command_line: proc_info.parent_command_line.clone(),
                    parent_chain: proc_info.parent_chain.clone(),
                    container_runtime: proc_info.container_runtime.clone(),
                    container_id: proc_info.container_id.clone(),
                });
            }
        }

        CorrelationResult {
            process: best_process,
            protected_hits,
        }
    }
}

fn count_matching_paths(
    process: &TrackedProcess,
    watched_root: &Path,
    touched_paths: &HashSet<String>,
) -> u32 {
    let mut exact_hits = 0u32;
    let mut root_hits = 0u32;

    for target_string in &process.open_paths {
        let target_path = Path::new(&target_string);
        if !target_path.starts_with(watched_root) {
            continue;
        }

        root_hits += 1;
        if touched_paths.contains(target_string.as_str()) {
            exact_hits += 1;
        }
    }

    exact_hits.saturating_mul(10).saturating_add(root_hits)
}

#[cfg(test)]
#[path = "../tests/unit/correlator_tests.rs"]
mod tests;
