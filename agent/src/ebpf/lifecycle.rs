use crate::config::{ContainmentConfig, TrustPolicyRule, TrustPolicyVisibility};
use crate::ebpf::events::{
    ContainerMount, MaintenanceActivity, OrchestratorMetadata, ProcessAncestor, ProcessTrustClass,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const TRUSTED_SYSTEM_EXEC_PREFIXES: &[&str] = &["/usr/", "/bin/", "/sbin/", "/lib/", "/nix/store/"];
const TRUSTED_PACKAGE_MANAGED_PATTERNS: &[&str] = &[
    "apt",
    "apt-get",
    "aptitude",
    "dpkg",
    "dpkg-preconfigure",
    "dpkg-deb",
    "dnf",
    "yum",
    "rpm",
    "apk",
    "pacman",
    "packagekitd",
    "snap",
    "snapd",
    "fwupd",
    "fwupdmgr",
    "systemd",
    "systemctl",
    "systemd-tmpfiles",
    "systemd-sysusers",
    "systemd-sysctl",
    "systemd-udevd",
    "unattended-upgrade",
    "unattended-upgrade-shutdown",
];
const PACKAGE_MANAGER_HELPER_PATTERNS: &[&str] = &[
    "apt",
    "apt-get",
    "aptitude",
    "dpkg",
    "dpkg-preconfigure",
    "dpkg-deb",
    "unattended-upgrade",
    "depmod",
    "cryptroot",
    "update-initramfs",
    "mkinitramfs",
    "ldconfig",
    "dracut",
    "rpm",
    "dnf",
    "yum",
    "apk",
    "pacman",
];
const SHELL_LIKE_PARENT_PATTERNS: &[&str] = &["sh", "bash", "dash", "zsh", "ash", "busybox"];
const LOCAL_EXEC_PREFIXES: &[&str] = &["/usr/local/", "/opt/", "/srv/", "/home/", "/root/"];
const TEMP_EXEC_PREFIXES: &[&str] = &["/tmp/", "/var/tmp/"];
const MAX_PARENT_CHAIN_DEPTH: usize = 6;
const MAX_OPEN_PATHS_PER_PROCESS: usize = 128;
const DOCKER_CONTAINER_CONFIG_ROOT: &str = "/var/lib/docker/containers";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedProcess {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub service_unit: Option<String>,
    pub first_seen_at: DateTime<Utc>,
    pub trust_class: ProcessTrustClass,
    pub trust_policy_name: Option<String>,
    pub maintenance_activity: Option<MaintenanceActivity>,
    pub trust_policy_visibility: TrustPolicyVisibility,
    pub package_name: Option<String>,
    pub package_manager: Option<String>,
    pub process_name: String,
    pub exe_path: String,
    pub command_line: String,
    pub parent_process_name: Option<String>,
    pub parent_command_line: Option<String>,
    pub parent_chain: Vec<ProcessAncestor>,
    pub container_runtime: Option<String>,
    pub container_id: Option<String>,
    pub container_image: Option<String>,
    pub orchestrator: OrchestratorMetadata,
    pub container_mounts: Vec<ContainerMount>,
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
    trust_policies: Vec<TrustPolicyRule>,
    previous: HashMap<u32, ProcessIdentity>,
    profiles: HashMap<String, ProcessProfileState>,
    container_contexts: HashMap<String, ResolvedContainerContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessIdentity {
    process_name: String,
    exe_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessProfileState {
    first_seen_at: DateTime<Utc>,
    package_name: Option<String>,
    package_manager: Option<String>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ProcessStatusMetadata {
    parent_pid: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct CgroupMetadata {
    service_unit: Option<String>,
    container_runtime: Option<String>,
    container_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageOwner {
    name: String,
    manager: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ResolvedContainerContext {
    image: Option<String>,
    orchestrator: OrchestratorMetadata,
    mounts: Vec<ContainerMount>,
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
            trust_policies: config.trust_policies.clone(),
            previous: HashMap::new(),
            profiles: HashMap::new(),
            container_contexts: HashMap::new(),
        }
    }

    pub async fn refresh(&mut self) -> Result<LifecycleSnapshot> {
        let watch_roots = self.watch_roots.clone();
        let protected_pid_allowlist = self.protected_pid_allowlist.clone();
        let mut processes = tokio::task::spawn_blocking(move || {
            collect_tracked_processes(&watch_roots, &protected_pid_allowlist)
        })
        .await
        .context("lifecycle task join failed")??;

        self.apply_profile_metadata(&mut processes, Utc::now());
        processes.retain(|_, process| !process.open_paths.is_empty());
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

    fn apply_profile_metadata(
        &mut self,
        processes: &mut HashMap<u32, TrackedProcess>,
        now: DateTime<Utc>,
    ) {
        for process in processes.values_mut() {
            let container_context = self.resolve_container_context(
                process.container_runtime.as_deref(),
                process.container_id.as_deref(),
            );
            if process.container_image.is_none() {
                process.container_image = container_context.image.clone();
            }
            if process.orchestrator == OrchestratorMetadata::default() {
                process.orchestrator = container_context.orchestrator.clone();
            }
            process.open_paths = filter_process_open_paths(
                &process.open_paths,
                &self.watch_roots,
                &container_context.mounts,
            );
            process.container_mounts = select_relevant_container_mounts(
                &container_context.mounts,
                &self.watch_roots,
                &process.open_paths,
            );
            let profile_key = process_profile_key(process);
            let profile = self.profiles.entry(profile_key).or_insert_with(|| {
                let package_owner = resolve_package_owner(&process.exe_path);
                ProcessProfileState {
                    first_seen_at: now,
                    package_name: process
                        .package_name
                        .clone()
                        .or_else(|| package_owner.as_ref().map(|owner| owner.name.clone())),
                    package_manager: process
                        .package_manager
                        .clone()
                        .or_else(|| package_owner.map(|owner| owner.manager)),
                }
            });
            process.first_seen_at = profile.first_seen_at;
            process.package_name = profile.package_name.clone();
            process.package_manager = profile.package_manager.clone();
            process.trust_class = classify_process_trust(process);
            process.trust_policy_name = None;
            process.trust_policy_visibility = TrustPolicyVisibility::Visible;
            if let Some(policy) = match_trust_policy(&self.trust_policies, process, now) {
                process.trust_class = policy.trust_class;
                process.trust_policy_name = Some(policy.name.clone());
                process.trust_policy_visibility = policy.visibility;
            }
            process.maintenance_activity = classify_maintenance_activity(process);
        }
    }

    fn resolve_container_context(
        &mut self,
        runtime: Option<&str>,
        container_id: Option<&str>,
    ) -> ResolvedContainerContext {
        let runtime = runtime
            .map(normalize_command_name)
            .filter(|value| !value.is_empty());
        let container_id = container_id
            .map(normalize_command_name)
            .filter(|value| !value.is_empty());
        let (Some(runtime), Some(container_id)) = (runtime, container_id) else {
            return ResolvedContainerContext::default();
        };
        let cache_key = format!("{runtime}:{container_id}");
        if let Some(context) = self.container_contexts.get(&cache_key) {
            return context.clone();
        }

        let resolved = resolve_container_context_uncached(&runtime, &container_id);
        self.container_contexts.insert(cache_key, resolved.clone());
        resolved
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
    let exe_path = read_exe_path(proc_dir.join("exe")).unwrap_or_else(|| process_name.clone());
    let command_line = read_cmdline(proc_dir.join("cmdline")).unwrap_or_else(|| exe_path.clone());
    let cgroup = read_cgroup_metadata(proc_dir.join("cgroup"));
    let open_paths = collect_open_paths(
        proc_dir.join("fd"),
        (!is_container_context(&cgroup)).then_some(watch_roots),
    );

    if open_paths.is_empty() {
        return None;
    }

    let status = read_status_metadata(proc_dir.join("status"));
    let (parent_process_name, parent_command_line, parent_chain) = status
        .parent_pid
        .and_then(inspect_parent_process)
        .unwrap_or((None, None, Vec::new()));

    let protected = pid == 1
        || matches_allowlist(&process_name, protected_pid_allowlist)
        || matches_allowlist(&exe_path, protected_pid_allowlist);

    Some(TrackedProcess {
        pid,
        parent_pid: status.parent_pid,
        uid: status.uid,
        gid: status.gid,
        service_unit: cgroup.service_unit,
        first_seen_at: Utc::now(),
        trust_class: ProcessTrustClass::Unknown,
        trust_policy_name: None,
        maintenance_activity: None,
        trust_policy_visibility: TrustPolicyVisibility::Visible,
        package_name: None,
        package_manager: None,
        process_name,
        exe_path,
        command_line,
        parent_process_name,
        parent_command_line,
        parent_chain,
        container_runtime: cgroup.container_runtime,
        container_id: cgroup.container_id,
        container_image: None,
        orchestrator: OrchestratorMetadata::default(),
        container_mounts: Vec::new(),
        open_paths,
        protected,
    })
}

fn collect_open_paths(fd_dir: PathBuf, watch_roots: Option<&[PathBuf]>) -> HashSet<String> {
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
        if !target_path.is_absolute() {
            continue;
        }
        if let Some(roots) = watch_roots {
            if !roots.iter().any(|root| target_path.starts_with(root)) {
                continue;
            }
        }
        open_paths.insert(normalized);
        if open_paths.len() >= MAX_OPEN_PATHS_PER_PROCESS {
            break;
        }
    }

    open_paths
}

fn is_container_context(metadata: &CgroupMetadata) -> bool {
    metadata.container_runtime.is_some() || metadata.container_id.is_some()
}

fn filter_process_open_paths(
    open_paths: &HashSet<String>,
    watch_roots: &[PathBuf],
    mounts: &[ContainerMount],
) -> HashSet<String> {
    open_paths
        .iter()
        .filter_map(|path| {
            if path_matches_watch_roots(path, watch_roots) {
                return Some(path.clone());
            }

            let mapped = map_container_open_path(path, mounts)?;
            path_matches_watch_roots(&mapped, watch_roots).then_some(mapped)
        })
        .collect()
}

fn select_relevant_container_mounts(
    mounts: &[ContainerMount],
    watch_roots: &[PathBuf],
    open_paths: &HashSet<String>,
) -> Vec<ContainerMount> {
    let mut relevant = Vec::new();

    for mount in mounts {
        let Some(source) = mount.source.as_deref() else {
            continue;
        };
        if source.is_empty() {
            continue;
        }

        let source_path = Path::new(source);
        let matches_watch_root = watch_roots
            .iter()
            .any(|root| source_path.starts_with(root) || root.starts_with(source_path));
        let matches_open_path = open_paths
            .iter()
            .map(Path::new)
            .any(|open_path| open_path.starts_with(source_path));

        if (matches_watch_root || matches_open_path) && !relevant.contains(mount) {
            relevant.push(mount.clone());
        }
    }

    relevant
}

fn path_matches_watch_roots(path: &str, watch_roots: &[PathBuf]) -> bool {
    let candidate = Path::new(path);
    watch_roots.iter().any(|root| candidate.starts_with(root))
}

fn map_container_open_path(path: &str, mounts: &[ContainerMount]) -> Option<String> {
    let candidate = Path::new(path);
    if !candidate.is_absolute() {
        return None;
    }

    mounts.iter().find_map(|mount| {
        let source = mount.source.as_deref().filter(|value| !value.is_empty())?;
        let destination = Path::new(&mount.destination);
        if !destination.is_absolute() {
            return None;
        }

        let suffix = candidate.strip_prefix(destination).ok()?;
        Some(Path::new(source).join(suffix).display().to_string())
    })
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

fn read_exe_path(path: PathBuf) -> Option<String> {
    let target = fs::read_link(path).ok()?;
    Some(normalize_proc_target(&target))
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

fn read_status_metadata(path: PathBuf) -> ProcessStatusMetadata {
    let Ok(content) = fs::read_to_string(path) else {
        return ProcessStatusMetadata::default();
    };

    let mut metadata = ProcessStatusMetadata::default();
    for line in content.lines() {
        if metadata.parent_pid.is_none() {
            metadata.parent_pid = parse_status_first_u32(line, "PPid:");
        }
        if metadata.uid.is_none() {
            metadata.uid = parse_status_first_u32(line, "Uid:");
        }
        if metadata.gid.is_none() {
            metadata.gid = parse_status_first_u32(line, "Gid:");
        }
        if metadata.parent_pid.is_some() && metadata.uid.is_some() && metadata.gid.is_some() {
            break;
        }
    }

    metadata
}

fn parse_status_first_u32(line: &str, prefix: &str) -> Option<u32> {
    let value = line.strip_prefix(prefix)?.split_whitespace().next()?;
    value.parse::<u32>().ok()
}

fn inspect_parent_process(
    ppid: u32,
) -> Option<(Option<String>, Option<String>, Vec<ProcessAncestor>)> {
    if ppid == 0 {
        return None;
    }

    let chain = inspect_parent_chain(Path::new("/proc"), ppid, MAX_PARENT_CHAIN_DEPTH);
    let parent_process_name = chain.first().and_then(|parent| parent.process_name.clone());
    let parent_command_line = chain.first().and_then(|parent| parent.command_line.clone());
    if parent_process_name.is_none() && parent_command_line.is_none() && chain.is_empty() {
        None
    } else {
        Some((parent_process_name, parent_command_line, chain))
    }
}

fn inspect_parent_chain(proc_root: &Path, ppid: u32, max_depth: usize) -> Vec<ProcessAncestor> {
    let mut chain = Vec::new();
    let mut next_pid = Some(ppid);
    let mut visited = HashSet::new();

    while let Some(pid) = next_pid {
        if pid == 0 || chain.len() >= max_depth || !visited.insert(pid) {
            break;
        }

        let proc_dir = proc_root.join(pid.to_string());
        let process_name = read_trimmed_file(proc_dir.join("comm"));
        let exe_path = read_exe_path(proc_dir.join("exe"));
        let command_line = read_cmdline(proc_dir.join("cmdline"));
        if process_name.is_none() && exe_path.is_none() && command_line.is_none() {
            break;
        }

        chain.push(ProcessAncestor {
            pid,
            process_name,
            exe_path,
            command_line,
        });

        next_pid = read_status_metadata(proc_dir.join("status")).parent_pid;
    }

    chain
}

fn process_profile_key(process: &TrackedProcess) -> String {
    let exe_path = process.exe_path.trim().to_ascii_lowercase();
    let service_unit = process
        .service_unit
        .as_deref()
        .unwrap_or("-")
        .trim()
        .to_ascii_lowercase();
    let container_identity = process
        .container_image
        .as_deref()
        .map(|image| format!("image:{}", normalize_command_name(image)))
        .or_else(|| {
            process
                .container_id
                .as_deref()
                .map(|id| format!("id:{}", normalize_command_name(id)))
        })
        .unwrap_or_else(|| "-".to_string());
    format!("{exe_path}|{service_unit}|{container_identity}")
}

fn normalize_proc_target(target: &Path) -> String {
    target
        .display()
        .to_string()
        .trim_end_matches(" (deleted)")
        .to_string()
}

fn classify_process_trust(process: &TrackedProcess) -> ProcessTrustClass {
    if is_temp_executable(&process.exe_path) {
        return ProcessTrustClass::Suspicious;
    }

    if process.package_name.is_some() {
        return ProcessTrustClass::TrustedPackageManaged;
    }

    if is_trusted_system_executable(&process.exe_path)
        && (process_matches_any_command_name(process, TRUSTED_PACKAGE_MANAGED_PATTERNS)
            || service_unit_matches_any(
                process.service_unit.as_deref(),
                TRUSTED_PACKAGE_MANAGED_PATTERNS,
            ))
    {
        return ProcessTrustClass::TrustedPackageManaged;
    }

    if is_trusted_system_process(process) {
        return ProcessTrustClass::TrustedSystem;
    }

    if is_allowed_local_process(process) {
        return ProcessTrustClass::AllowedLocal;
    }

    ProcessTrustClass::Unknown
}

fn classify_maintenance_activity(process: &TrackedProcess) -> Option<MaintenanceActivity> {
    if process_matches_any_command_name(process, PACKAGE_MANAGER_HELPER_PATTERNS) {
        return Some(MaintenanceActivity::PackageManagerHelper);
    }

    let trusted_class = matches!(
        process.trust_class,
        ProcessTrustClass::TrustedSystem | ProcessTrustClass::TrustedPackageManaged
    );

    if trusted_class
        && (process_matches_any_command_name(process, TRUSTED_PACKAGE_MANAGED_PATTERNS)
            || service_unit_matches_any(
                process.service_unit.as_deref(),
                TRUSTED_PACKAGE_MANAGED_PATTERNS,
            ))
        && is_trusted_system_executable(&process.exe_path)
        && !is_temp_executable(&process.exe_path)
        && !has_shell_like_parent(process)
    {
        return Some(MaintenanceActivity::TrustedMaintenance);
    }

    None
}

fn match_trust_policy<'a>(
    policies: &'a [TrustPolicyRule],
    process: &TrackedProcess,
    now: DateTime<Utc>,
) -> Option<&'a TrustPolicyRule> {
    policies
        .iter()
        .find(|policy| trust_policy_matches(policy, process, now))
}

fn trust_policy_matches(
    policy: &TrustPolicyRule,
    process: &TrackedProcess,
    now: DateTime<Utc>,
) -> bool {
    let exe_match = !policy.exe_paths.is_empty()
        && policy
            .exe_paths
            .iter()
            .any(|exe_path| exe_path_matches_policy(&process.exe_path, exe_path));
    let service_unit_match = !policy.service_units.is_empty()
        && policy.service_units.iter().any(|service_unit| {
            service_unit_matches_policy(process.service_unit.as_deref(), service_unit)
        });
    let package_name_match = !policy.package_names.is_empty()
        && policy.package_names.iter().any(|package_name| {
            package_name_matches_policy(process.package_name.as_deref(), package_name)
        });
    let container_image_match = !policy.container_images.is_empty()
        && policy.container_images.iter().any(|container_image| {
            container_image_matches_policy(process.container_image.as_deref(), container_image)
        });

    if !exe_match && !service_unit_match && !package_name_match && !container_image_match {
        return false;
    }

    policy.maintenance_windows.is_empty()
        || policy
            .maintenance_windows
            .iter()
            .any(|window| window.matches(now))
}

fn is_trusted_system_process(process: &TrackedProcess) -> bool {
    is_trusted_system_executable(&process.exe_path)
        && (process.pid == 1
            || normalize_command_name(&process.process_name) == "systemd"
            || process
                .parent_process_name
                .as_deref()
                .map(normalize_command_name)
                .as_deref()
                == Some("systemd"))
}

fn is_allowed_local_process(process: &TrackedProcess) -> bool {
    let exe_path = process.exe_path.trim();
    LOCAL_EXEC_PREFIXES
        .iter()
        .any(|prefix| exe_path.starts_with(prefix))
        || process.service_unit.is_some()
        || process.container_id.is_some()
}

fn is_trusted_system_executable(path: &str) -> bool {
    let trimmed = path.trim();
    TRUSTED_SYSTEM_EXEC_PREFIXES
        .iter()
        .any(|prefix| trimmed.starts_with(prefix))
}

fn is_temp_executable(path: &str) -> bool {
    let trimmed = path.trim();
    trimmed == "/tmp"
        || trimmed == "/var/tmp"
        || TEMP_EXEC_PREFIXES
            .iter()
            .any(|prefix| trimmed.starts_with(prefix))
}

fn process_matches_any_command_name(process: &TrackedProcess, patterns: &[&str]) -> bool {
    matches_any_command_name(
        [
            Some(process.process_name.as_str()),
            path_basename(&process.exe_path),
            argv0_basename(&process.command_line),
        ]
        .into_iter()
        .flatten(),
        patterns,
    )
}

fn has_shell_like_parent(process: &TrackedProcess) -> bool {
    process.parent_chain.iter().any(|parent| {
        matches_any_command_name(
            [
                parent.process_name.as_deref(),
                parent.exe_path.as_deref().and_then(path_basename),
                parent.command_line.as_deref().and_then(argv0_basename),
            ]
            .into_iter()
            .flatten(),
            SHELL_LIKE_PARENT_PATTERNS,
        )
    }) || matches_any_command_name(
        [
            process.parent_process_name.as_deref(),
            process
                .parent_command_line
                .as_deref()
                .and_then(argv0_basename),
        ]
        .into_iter()
        .flatten(),
        SHELL_LIKE_PARENT_PATTERNS,
    )
}

fn service_unit_matches_any(service_unit: Option<&str>, patterns: &[&str]) -> bool {
    let Some(service_unit) = service_unit else {
        return false;
    };

    let normalized = normalize_service_unit_name(service_unit);
    !normalized.is_empty()
        && patterns
            .iter()
            .map(|pattern| normalize_service_unit_name(pattern))
            .filter(|pattern| !pattern.is_empty())
            .any(|pattern| pattern == normalized)
}

fn service_unit_matches_policy(service_unit: Option<&str>, configured_value: &str) -> bool {
    let Some(service_unit) = service_unit else {
        return false;
    };

    let normalized = normalize_service_unit_name(service_unit);
    let configured = normalize_service_unit_name(configured_value);
    !normalized.is_empty() && normalized == configured
}

fn matches_any_command_name<'a>(
    candidates: impl IntoIterator<Item = &'a str>,
    patterns: &[&str],
) -> bool {
    let normalized_patterns = patterns
        .iter()
        .map(|pattern| normalize_command_name(pattern))
        .filter(|pattern| !pattern.is_empty())
        .collect::<HashSet<_>>();

    candidates.into_iter().any(|candidate| {
        let normalized = normalize_command_name(candidate);
        !normalized.is_empty() && normalized_patterns.contains(&normalized)
    })
}

fn path_basename(value: &str) -> Option<&str> {
    Path::new(value)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
}

fn argv0_basename(command_line: &str) -> Option<&str> {
    let argv0 = command_line.split_whitespace().next()?;
    path_basename(argv0).or_else(|| (!argv0.is_empty()).then_some(argv0))
}

fn exe_path_matches_policy(exe_path: &str, configured_value: &str) -> bool {
    let normalized = normalize_policy_path(exe_path);
    let configured = normalize_policy_path(configured_value);
    !normalized.is_empty() && normalized == configured
}

fn package_name_matches_policy(package_name: Option<&str>, configured_value: &str) -> bool {
    let Some(package_name) = package_name else {
        return false;
    };

    let normalized = normalize_command_name(package_name);
    let configured = normalize_command_name(configured_value);
    !normalized.is_empty() && normalized == configured
}

fn container_image_matches_policy(container_image: Option<&str>, configured_value: &str) -> bool {
    let Some(container_image) = container_image else {
        return false;
    };

    let normalized = normalize_command_name(container_image);
    let configured = normalize_command_name(configured_value);
    !normalized.is_empty() && normalized == configured
}

fn normalize_command_name(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn normalize_service_unit_name(value: &str) -> String {
    normalize_command_name(value.trim_end_matches(".service"))
}

fn normalize_policy_path(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        String::new()
    } else if trimmed.len() == 1 {
        trimmed.to_string()
    } else {
        trimmed.trim_end_matches('/').to_string()
    }
}

fn resolve_package_owner(exe_path: &str) -> Option<PackageOwner> {
    let normalized = normalize_policy_path(exe_path);
    let path = Path::new(&normalized);
    if normalized.is_empty() || !path.is_absolute() {
        return None;
    }

    query_package_owner(
        "dpkg-query",
        &["-S", normalized.as_str()],
        parse_dpkg_owner_output,
        "dpkg",
    )
    .or_else(|| {
        query_package_owner(
            "rpm",
            &["-qf", normalized.as_str()],
            parse_rpm_owner_output,
            "rpm",
        )
    })
    .or_else(|| {
        query_package_owner(
            "pacman",
            &["-Qo", normalized.as_str()],
            parse_pacman_owner_output,
            "pacman",
        )
    })
    .or_else(|| {
        query_package_owner(
            "apk",
            &["info", "--who-owns", normalized.as_str()],
            parse_apk_owner_output,
            "apk",
        )
    })
}

fn resolve_container_context_uncached(
    runtime: &str,
    container_id: &str,
) -> ResolvedContainerContext {
    match runtime {
        "docker" => read_docker_container_context_from_root(
            Path::new(DOCKER_CONTAINER_CONFIG_ROOT),
            container_id,
        )
        .unwrap_or_else(|| inspect_container_context("docker", container_id).unwrap_or_default()),
        "podman" => inspect_container_context("podman", container_id).unwrap_or_default(),
        "containerd" => inspect_container_context("crictl", container_id)
            .or_else(|| inspect_container_context("nerdctl", container_id))
            .unwrap_or_default(),
        "kubernetes" | "crio" => {
            inspect_container_context("crictl", container_id).unwrap_or_default()
        }
        _ => ResolvedContainerContext::default(),
    }
}

fn read_docker_container_context_from_root(
    root: &Path,
    container_id: &str,
) -> Option<ResolvedContainerContext> {
    let container_dir = docker_container_dir(root, container_id)?;
    let content = fs::read_to_string(container_dir.join("config.v2.json")).ok()?;
    parse_container_inspect_context(&content)
}

#[cfg_attr(not(test), allow(dead_code))]
fn read_docker_container_image_from_root(root: &Path, container_id: &str) -> Option<String> {
    read_docker_container_context_from_root(root, container_id).and_then(|context| context.image)
}

fn docker_container_dir(root: &Path, container_id: &str) -> Option<PathBuf> {
    let exact = root.join(container_id);
    if exact.is_dir() {
        return Some(exact);
    }

    let normalized = normalize_command_name(container_id);
    let matches = fs::read_dir(root)
        .ok()?
        .flatten()
        .filter_map(|entry| {
            let file_type = entry.file_type().ok()?;
            if !file_type.is_dir() {
                return None;
            }

            let name = entry.file_name().to_string_lossy().into_owned();
            let lower = normalize_command_name(&name);
            (lower.starts_with(&normalized) || normalized.starts_with(&lower))
                .then_some(entry.path())
        })
        .collect::<Vec<_>>();

    if matches.len() == 1 {
        matches.into_iter().next()
    } else {
        None
    }
}

fn inspect_container_context(
    program: &str,
    container_id: &str,
) -> Option<ResolvedContainerContext> {
    let output = Command::new(program)
        .args(["inspect", container_id])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_container_inspect_context(&stdout)
}

#[cfg_attr(not(test), allow(dead_code))]
fn parse_container_inspect_image(content: &str) -> Option<String> {
    parse_container_inspect_context(content).and_then(|context| context.image)
}

fn parse_container_inspect_context(content: &str) -> Option<ResolvedContainerContext> {
    let value: Value = serde_json::from_str(content).ok()?;
    parse_container_inspect_context_value(&value)
}

fn parse_container_inspect_context_value(value: &Value) -> Option<ResolvedContainerContext> {
    if let Some(entries) = value.as_array() {
        return entries
            .iter()
            .find_map(parse_container_inspect_context_value);
    }

    let image = [
        "/Config/Image",
        "/ImageName",
        "/status/image/image",
        "/info/config/image/image",
        "/status/imageRef",
        "/Image",
    ]
    .into_iter()
    .find_map(|pointer| {
        value
            .pointer(pointer)
            .and_then(Value::as_str)
            .and_then(normalize_container_image)
    });
    let orchestrator = parse_orchestrator_metadata(value);
    let mounts = parse_container_mounts(value);

    if image.is_none() && orchestrator == OrchestratorMetadata::default() && mounts.is_empty() {
        None
    } else {
        Some(ResolvedContainerContext {
            image,
            orchestrator,
            mounts,
        })
    }
}

fn normalize_container_image(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_matches('"');
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn parse_orchestrator_metadata(value: &Value) -> OrchestratorMetadata {
    let labels = extract_container_labels(value);

    if let Some(namespace) = labels
        .get("io.kubernetes.pod.namespace")
        .and_then(Value::as_str)
    {
        return OrchestratorMetadata {
            platform: Some("kubernetes".to_string()),
            namespace: normalize_non_empty_string(namespace),
            workload: labels
                .get("io.kubernetes.pod.name")
                .and_then(Value::as_str)
                .and_then(normalize_non_empty_string),
        };
    }

    if let Some(project) = labels
        .get("com.docker.compose.project")
        .and_then(Value::as_str)
    {
        return OrchestratorMetadata {
            platform: Some("docker_compose".to_string()),
            namespace: normalize_non_empty_string(project),
            workload: labels
                .get("com.docker.compose.service")
                .and_then(Value::as_str)
                .and_then(normalize_non_empty_string),
        };
    }

    OrchestratorMetadata::default()
}

fn extract_container_labels(value: &Value) -> &serde_json::Map<String, Value> {
    for pointer in [
        "/Config/Labels",
        "/Config/config/Labels",
        "/status/labels",
        "/info/config/labels",
        "/labels",
    ] {
        if let Some(labels) = value.pointer(pointer).and_then(Value::as_object) {
            return labels;
        }
    }

    static EMPTY_LABELS: std::sync::OnceLock<serde_json::Map<String, Value>> =
        std::sync::OnceLock::new();
    EMPTY_LABELS.get_or_init(serde_json::Map::new)
}

fn parse_container_mounts(value: &Value) -> Vec<ContainerMount> {
    if let Some(mounts) = value.pointer("/Mounts").and_then(Value::as_array) {
        return mounts
            .iter()
            .filter_map(parse_container_mount)
            .collect::<Vec<_>>();
    }

    if let Some(mount_points) = value.pointer("/MountPoints").and_then(Value::as_object) {
        return mount_points
            .values()
            .filter_map(parse_container_mount)
            .collect::<Vec<_>>();
    }

    if let Some(mounts) = value.pointer("/status/mounts").and_then(Value::as_array) {
        return mounts
            .iter()
            .filter_map(parse_container_mount)
            .collect::<Vec<_>>();
    }

    Vec::new()
}

fn parse_container_mount(value: &Value) -> Option<ContainerMount> {
    let destination = [
        value.get("Destination"),
        value.get("destination"),
        value.get("container_path"),
    ]
    .into_iter()
    .flatten()
    .find_map(Value::as_str)
    .and_then(normalize_non_empty_string)?;
    let mount_type = [
        value.get("Type"),
        value.get("type"),
        value.get("mount_type"),
    ]
    .into_iter()
    .flatten()
    .find_map(Value::as_str)
    .and_then(normalize_non_empty_string)
    .unwrap_or_else(|| "unknown".to_string());

    Some(ContainerMount {
        mount_type,
        source: [
            value.get("Source"),
            value.get("source"),
            value.get("host_path"),
        ]
        .into_iter()
        .flatten()
        .find_map(Value::as_str)
        .and_then(normalize_non_empty_string),
        destination,
        name: [value.get("Name"), value.get("name")]
            .into_iter()
            .flatten()
            .find_map(Value::as_str)
            .and_then(normalize_non_empty_string),
    })
}

fn normalize_non_empty_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn query_package_owner(
    program: &str,
    args: &[&str],
    parse: fn(&str) -> Option<String>,
    manager: &str,
) -> Option<PackageOwner> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse(&stdout).map(|name| PackageOwner {
        name,
        manager: manager.to_string(),
    })
}

fn parse_dpkg_owner_output(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let package = line.split_once(':')?.0.trim();
        (!package.is_empty()).then(|| package.to_string())
    })
}

fn parse_rpm_owner_output(output: &str) -> Option<String> {
    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with("file "))
        .map(|line| line.to_string())
}

fn parse_pacman_owner_output(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let owner = line.split(" is owned by ").nth(1)?.trim();
        owner.split_whitespace().next().map(str::to_string)
    })
}

fn parse_apk_owner_output(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let owner = line.split(" is owned by ").nth(1)?.trim();
        owner.split_whitespace().next().map(str::to_string)
    })
}

fn read_cgroup_metadata(path: PathBuf) -> CgroupMetadata {
    let Ok(content) = fs::read_to_string(path) else {
        return CgroupMetadata::default();
    };

    parse_cgroup_metadata(&content)
}

fn parse_cgroup_metadata(content: &str) -> CgroupMetadata {
    let mut runtime = None;
    let mut container_id = None;
    let mut service_unit = None;

    for line in content.lines() {
        let lower = line.to_ascii_lowercase();
        if runtime.is_none() {
            runtime = if lower.contains("docker") {
                Some("docker".to_string())
            } else if lower.contains("containerd") || lower.contains("cri-containerd") {
                Some("containerd".to_string())
            } else if lower.contains("crio") {
                Some("crio".to_string())
            } else if lower.contains("kubepods") {
                Some("kubernetes".to_string())
            } else if lower.contains("libpod") || lower.contains("podman") {
                Some("podman".to_string())
            } else {
                None
            };
        }

        if container_id.is_none() {
            container_id = extract_container_id(line);
        }

        if service_unit.is_none() {
            service_unit = extract_service_unit(line);
        }

        if runtime.is_some() && container_id.is_some() && service_unit.is_some() {
            break;
        }
    }

    CgroupMetadata {
        service_unit,
        container_runtime: runtime,
        container_id,
    }
}

fn extract_service_unit(value: &str) -> Option<String> {
    value.split('/').find_map(|segment| {
        let trimmed = segment.trim();
        if trimmed.ends_with(".service") {
            Some(trimmed.to_string())
        } else {
            None
        }
    })
}

fn extract_container_id(value: &str) -> Option<String> {
    value.split('/').find_map(parse_container_segment)
}

fn parse_container_segment(segment: &str) -> Option<String> {
    let trimmed = segment.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut candidate = trimmed.trim_end_matches(".scope");
    for prefix in ["docker-", "cri-containerd-", "libpod-", "crio-", "podman-"] {
        if let Some(stripped) = candidate.strip_prefix(prefix) {
            candidate = stripped;
            break;
        }
    }

    if is_container_id(candidate) {
        Some(candidate.to_string())
    } else {
        None
    }
}

fn is_container_id(candidate: &str) -> bool {
    let len = candidate.len();
    len >= 12 && candidate.chars().all(|ch| ch.is_ascii_hexdigit())
}

#[cfg(test)]
#[path = "../../tests/unit/ebpf/lifecycle_tests.rs"]
mod tests;
