use crate::config::ContainmentConfig;
use crate::ebpf::events::{FileActivityBatch, ProcessInfo};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CorrelationResult {
    pub process: Option<ProcessInfo>,
    pub protected_hits: u32,
}

#[derive(Debug)]
pub struct ProcessCorrelator {
    protected_pid_allowlist: Vec<String>,
}

impl ProcessCorrelator {
    pub fn new(config: &ContainmentConfig) -> Self {
        Self {
            protected_pid_allowlist: config
                .protected_pid_allowlist
                .iter()
                .map(|value| value.to_ascii_lowercase())
                .collect(),
        }
    }

    pub fn correlate(&self, batch: &FileActivityBatch) -> CorrelationResult {
        let root = Path::new(&batch.watched_root);
        let touched_paths = batch
            .touched_paths
            .iter()
            .map(|path| path.to_string())
            .collect::<HashSet<_>>();

        let Ok(entries) = fs::read_dir("/proc") else {
            return CorrelationResult::default();
        };

        let mut best_process = None;
        let mut best_hits = 0u32;
        let mut protected_hits = 0u32;

        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(pid_str) = name.to_str() else {
                continue;
            };
            let Ok(pid) = pid_str.parse::<u32>() else {
                continue;
            };

            let Some(proc_info) = self.inspect_process(pid, root, &touched_paths) else {
                continue;
            };

            if proc_info.protected {
                protected_hits = protected_hits.max(proc_info.correlation_hits);
                continue;
            }

            if proc_info.correlation_hits > best_hits {
                best_hits = proc_info.correlation_hits;
                best_process = Some(ProcessInfo {
                    pid,
                    process_name: proc_info.process_name,
                    exe_path: proc_info.exe_path,
                    command_line: proc_info.command_line,
                    correlation_hits: proc_info.correlation_hits,
                });
            }
        }

        CorrelationResult {
            process: best_process,
            protected_hits,
        }
    }

    fn inspect_process(
        &self,
        pid: u32,
        watched_root: &Path,
        touched_paths: &HashSet<String>,
    ) -> Option<ProcessObservation> {
        let proc_dir = PathBuf::from("/proc").join(pid.to_string());
        let process_name = read_trimmed_file(proc_dir.join("comm"))?;
        let exe_path = fs::read_link(proc_dir.join("exe"))
            .ok()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| process_name.clone());
        let command_line =
            read_cmdline(proc_dir.join("cmdline")).unwrap_or_else(|| exe_path.clone());
        let correlation_hits = count_matching_fds(proc_dir.join("fd"), watched_root, touched_paths);

        if correlation_hits == 0 {
            return None;
        }

        let protected =
            pid == 1 || self.matches_allowlist(&process_name) || self.matches_allowlist(&exe_path);

        Some(ProcessObservation {
            process_name,
            exe_path,
            command_line,
            correlation_hits,
            protected,
        })
    }

    fn matches_allowlist(&self, value: &str) -> bool {
        let haystack = value.to_ascii_lowercase();
        self.protected_pid_allowlist
            .iter()
            .any(|needle| haystack.contains(needle))
    }
}

#[derive(Debug)]
struct ProcessObservation {
    process_name: String,
    exe_path: String,
    command_line: String,
    correlation_hits: u32,
    protected: bool,
}

fn count_matching_fds(
    fd_dir: PathBuf,
    watched_root: &Path,
    touched_paths: &HashSet<String>,
) -> u32 {
    let Ok(entries) = fs::read_dir(fd_dir) else {
        return 0;
    };

    let mut exact_hits = 0u32;
    let mut root_hits = 0u32;

    for entry in entries.flatten() {
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };

        let target_string = normalize_fd_target(&target);
        let target_path = Path::new(&target_string);
        if !target_path.starts_with(watched_root) {
            continue;
        }

        root_hits += 1;
        if touched_paths.contains(&target_string) {
            exact_hits += 1;
        }
    }

    exact_hits.saturating_mul(10).saturating_add(root_hits)
}

fn normalize_fd_target(target: &Path) -> String {
    let raw = target.display().to_string();
    raw.trim_end_matches(" (deleted)").to_string()
}

fn read_trimmed_file(path: PathBuf) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let value = content.trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn read_cmdline(path: PathBuf) -> Option<String> {
    let content = fs::read(path).ok()?;
    let args = content
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect::<Vec<_>>();
    if args.is_empty() {
        None
    } else {
        Some(args.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ContainmentConfig;

    #[test]
    fn protected_allowlist_matches_agent_binary_name() {
        let correlator = ProcessCorrelator::new(&ContainmentConfig::default());
        assert!(correlator.matches_allowlist("/usr/local/bin/bannkenn-agent"));
        assert!(correlator.matches_allowlist("systemd-journald"));
        assert!(!correlator.matches_allowlist("/usr/bin/python3"));
    }

    #[test]
    fn deleted_fd_suffix_is_removed_before_matching() {
        let normalized = normalize_fd_target(Path::new("/tmp/example.txt (deleted)"));
        assert_eq!(normalized, "/tmp/example.txt");
    }
}
