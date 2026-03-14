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
                    process_name: proc_info.process_name.clone(),
                    exe_path: proc_info.exe_path.clone(),
                    command_line: proc_info.command_line.clone(),
                    correlation_hits,
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
mod tests {
    use super::*;
    use crate::ebpf::lifecycle::{LifecycleEvent, TrackedProcess};

    #[test]
    fn correlator_prefers_non_protected_process_with_exact_path_hits() {
        let correlator = ProcessCorrelator::new();
        let batch = FileActivityBatch {
            timestamp: chrono::Utc::now(),
            source: "userspace_polling".to_string(),
            watched_root: "/srv/data".to_string(),
            poll_interval_ms: 1000,
            file_ops: crate::ebpf::events::FileOperationCounts {
                renamed: 3,
                ..Default::default()
            },
            touched_paths: vec!["/srv/data/file-a".to_string()],
            protected_paths_touched: Vec::new(),
            bytes_written: 0,
            io_rate_bytes_per_sec: 0,
        };
        let snapshot = LifecycleSnapshot {
            processes: vec![
                TrackedProcess {
                    pid: 1,
                    process_name: "systemd".to_string(),
                    exe_path: "/usr/lib/systemd/systemd".to_string(),
                    command_line: "systemd".to_string(),
                    open_paths: HashSet::from(["/srv/data/file-a".to_string()]),
                    protected: true,
                },
                TrackedProcess {
                    pid: 42,
                    process_name: "python3".to_string(),
                    exe_path: "/usr/bin/python3".to_string(),
                    command_line: "python3 encrypt.py".to_string(),
                    open_paths: HashSet::from([
                        "/srv/data/file-a".to_string(),
                        "/srv/data/file-b".to_string(),
                    ]),
                    protected: false,
                },
            ],
            events: vec![LifecycleEvent::Exec {
                pid: 42,
                process_name: "python3".to_string(),
                exe_path: "/usr/bin/python3".to_string(),
            }],
        };

        let result = correlator.correlate(&batch, &snapshot);
        assert_eq!(result.process.expect("process").pid, 42);
        assert!(result.protected_hits > 0);
    }
}
