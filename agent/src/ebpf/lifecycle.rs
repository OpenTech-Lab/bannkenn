use crate::config::ContainmentConfig;
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedProcess {
    pub pid: u32,
    pub process_name: String,
    pub exe_path: String,
    pub command_line: String,
    pub open_paths: HashSet<String>,
    pub protected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleEvent {
    Exec {
        pid: u32,
        process_name: String,
        exe_path: String,
    },
    Exit {
        pid: u32,
        process_name: String,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LifecycleSnapshot {
    pub processes: Vec<TrackedProcess>,
    pub events: Vec<LifecycleEvent>,
}

#[derive(Debug)]
pub struct ProcessLifecycleTracker {
    watch_roots: Vec<PathBuf>,
    protected_pid_allowlist: Vec<String>,
    previous: HashMap<u32, ProcessIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessIdentity {
    process_name: String,
    exe_path: String,
}

impl ProcessLifecycleTracker {
    pub fn new(config: &ContainmentConfig) -> Self {
        let watch_roots = config
            .watch_paths
            .iter()
            .filter_map(|path| normalize_path(path))
            .collect::<Vec<_>>();

        Self {
            watch_roots,
            protected_pid_allowlist: config
                .protected_pid_allowlist
                .iter()
                .map(|entry| entry.to_ascii_lowercase())
                .collect(),
            previous: HashMap::new(),
        }
    }

    pub async fn refresh(&mut self) -> Result<LifecycleSnapshot> {
        let watch_roots = self.watch_roots.clone();
        let protected_pid_allowlist = self.protected_pid_allowlist.clone();
        let processes = tokio::task::spawn_blocking(move || {
            collect_tracked_processes(&watch_roots, &protected_pid_allowlist)
        })
        .await
        .context("lifecycle task join failed")??;

        let events = diff_lifecycle_events(&self.previous, &processes);
        self.previous = processes
            .iter()
            .map(|(pid, process)| {
                (
                    *pid,
                    ProcessIdentity {
                        process_name: process.process_name.clone(),
                        exe_path: process.exe_path.clone(),
                    },
                )
            })
            .collect();

        Ok(LifecycleSnapshot {
            processes: processes.into_values().collect(),
            events,
        })
    }
}

fn collect_tracked_processes(
    watch_roots: &[PathBuf],
    protected_pid_allowlist: &[String],
) -> Result<HashMap<u32, TrackedProcess>> {
    let mut processes = HashMap::new();
    let entries = fs::read_dir("/proc").context("failed to read /proc")?;

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid_str) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };

        let Some(process) = inspect_process(pid, watch_roots, protected_pid_allowlist) else {
            continue;
        };
        processes.insert(pid, process);
    }

    Ok(processes)
}

fn inspect_process(
    pid: u32,
    watch_roots: &[PathBuf],
    protected_pid_allowlist: &[String],
) -> Option<TrackedProcess> {
    let proc_dir = PathBuf::from("/proc").join(pid.to_string());
    let process_name = read_trimmed_file(proc_dir.join("comm"))?;
    let exe_path = fs::read_link(proc_dir.join("exe"))
        .ok()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| process_name.clone());
    let command_line = read_cmdline(proc_dir.join("cmdline")).unwrap_or_else(|| exe_path.clone());
    let open_paths = collect_open_paths(proc_dir.join("fd"), watch_roots);

    if open_paths.is_empty() {
        return None;
    }

    let protected = pid == 1
        || matches_allowlist(&process_name, protected_pid_allowlist)
        || matches_allowlist(&exe_path, protected_pid_allowlist);

    Some(TrackedProcess {
        pid,
        process_name,
        exe_path,
        command_line,
        open_paths,
        protected,
    })
}

fn collect_open_paths(fd_dir: PathBuf, watch_roots: &[PathBuf]) -> HashSet<String> {
    let Ok(entries) = fs::read_dir(fd_dir) else {
        return HashSet::new();
    };

    let mut open_paths = HashSet::new();
    for entry in entries.flatten() {
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        let normalized = normalize_fd_target(&target);
        let target_path = Path::new(&normalized);
        if watch_roots.iter().any(|root| target_path.starts_with(root)) {
            open_paths.insert(normalized);
        }
    }

    open_paths
}

fn diff_lifecycle_events(
    previous: &HashMap<u32, ProcessIdentity>,
    current: &HashMap<u32, TrackedProcess>,
) -> Vec<LifecycleEvent> {
    let mut events = Vec::new();

    for (pid, process) in current {
        match previous.get(pid) {
            None => events.push(LifecycleEvent::Exec {
                pid: *pid,
                process_name: process.process_name.clone(),
                exe_path: process.exe_path.clone(),
            }),
            Some(identity)
                if identity.process_name != process.process_name
                    || identity.exe_path != process.exe_path =>
            {
                events.push(LifecycleEvent::Exec {
                    pid: *pid,
                    process_name: process.process_name.clone(),
                    exe_path: process.exe_path.clone(),
                });
            }
            Some(_) => {}
        }
    }

    for (pid, identity) in previous {
        if !current.contains_key(pid) {
            events.push(LifecycleEvent::Exit {
                pid: *pid,
                process_name: identity.process_name.clone(),
            });
        }
    }

    events
}

fn matches_allowlist(value: &str, protected_pid_allowlist: &[String]) -> bool {
    let haystack = value.to_ascii_lowercase();
    protected_pid_allowlist
        .iter()
        .any(|needle| haystack.contains(needle))
}

fn normalize_fd_target(target: &Path) -> String {
    let raw = target.display().to_string();
    raw.trim_end_matches(" (deleted)").to_string()
}

fn normalize_path(path: &str) -> Option<PathBuf> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }

    let candidate = PathBuf::from(trimmed);
    Some(fs::canonicalize(&candidate).unwrap_or(candidate))
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

    fn tracked_process(pid: u32, process_name: &str, exe_path: &str) -> TrackedProcess {
        TrackedProcess {
            pid,
            process_name: process_name.to_string(),
            exe_path: exe_path.to_string(),
            command_line: exe_path.to_string(),
            open_paths: HashSet::from(["/srv/data/file.txt".to_string()]),
            protected: false,
        }
    }

    #[test]
    fn lifecycle_diff_detects_exec_exit_and_reexec() {
        let previous = HashMap::from([
            (
                10,
                ProcessIdentity {
                    process_name: "bash".to_string(),
                    exe_path: "/usr/bin/bash".to_string(),
                },
            ),
            (
                20,
                ProcessIdentity {
                    process_name: "python3".to_string(),
                    exe_path: "/usr/bin/python3".to_string(),
                },
            ),
        ]);
        let current = HashMap::from([
            (20, tracked_process(20, "python3", "/usr/bin/python3.12")),
            (30, tracked_process(30, "ransom", "/tmp/ransom")),
        ]);

        let events = diff_lifecycle_events(&previous, &current);
        assert!(events.contains(&LifecycleEvent::Exec {
            pid: 20,
            process_name: "python3".to_string(),
            exe_path: "/usr/bin/python3.12".to_string(),
        }));
        assert!(events.contains(&LifecycleEvent::Exec {
            pid: 30,
            process_name: "ransom".to_string(),
            exe_path: "/tmp/ransom".to_string(),
        }));
        assert!(events.contains(&LifecycleEvent::Exit {
            pid: 10,
            process_name: "bash".to_string(),
        }));
    }

    #[test]
    fn allowlist_matching_is_case_insensitive() {
        assert!(matches_allowlist(
            "/usr/local/bin/BannKenn-Agent",
            &["bannkenn-agent".to_string()]
        ));
        assert!(!matches_allowlist(
            "/usr/bin/python3",
            &["systemd".to_string()]
        ));
    }
}
