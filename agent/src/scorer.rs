use crate::config::ContainmentConfig;
use crate::correlator::CorrelationResult;
use crate::ebpf::events::{
    BehaviorEvent, BehaviorLevel, FileActivityBatch, FileOperationCounts, MaintenanceActivity,
    ProcessInfo,
};
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use std::path::Path;

const TEMP_ROOTS: &[&str] = &["/tmp", "/var/tmp"];
const KNOWN_JAVA_RUNTIME_MARKERS: &[&str] =
    &["opensearch", "wazuh-indexer", "org.opensearch", "solr"];
const SHELL_LIKE_PARENT_PATTERNS: &[&str] = &["sh", "bash", "dash", "zsh", "ash", "busybox"];
const TRUSTED_EXEC_PREFIXES: &[&str] = &["/usr/", "/bin/", "/sbin/", "/lib/", "/nix/store/"];
const MAINTENANCE_PATH_PREFIXES: &[&str] = &[
    "/usr",
    "/etc",
    "/lib",
    "/boot",
    "/run/systemd",
    "/var/lib/dpkg",
    "/var/lib/apt",
    "/var/cache/apt",
    "/var/lib/snapd",
    "/var/lib/fwupd",
    "/snap",
];
const AGENT_INTERNAL_PATTERNS: &[&str] = &["bannkenn-agent"];
const AGENT_INTERNAL_PATH_PREFIXES: &[&str] = &[
    "/etc/bannkenn",
    "/var/lib/bannkenn",
    "/usr/lib/bannkenn",
    "/usr/local/lib/bannkenn",
    "/opt/bannkenn",
    "/.config/bannkenn",
];
const RENAME_BURST_GRACE: u32 = 3;
const DELETE_BURST_GRACE: u32 = 2;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ScoreAdjustment {
    penalty: u32,
    bonus: u32,
    reasons: Vec<String>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ScoreComponents {
    protected_path: u32,
    rename: u32,
    write: u32,
    delete: u32,
    throughput: u32,
}

pub trait Scorer {
    fn score(&self, batch: &FileActivityBatch, correlation: &CorrelationResult) -> BehaviorEvent;
}

#[derive(Debug, Clone)]
pub struct CompositeBehaviorScorer {
    suspicious_score: u32,
    throttle_score: u32,
    fuse_score: u32,
    rename_score: u32,
    write_score: u32,
    delete_score: u32,
    protected_path_bonus: u32,
    unknown_process_bonus: u32,
    bytes_per_score: u64,
}

impl CompositeBehaviorScorer {
    pub fn from_config(config: &ContainmentConfig) -> Self {
        Self {
            suspicious_score: config.suspicious_score,
            throttle_score: config.throttle_score,
            fuse_score: config.fuse_score,
            rename_score: config.rename_score,
            write_score: config.write_score,
            delete_score: config.delete_score,
            protected_path_bonus: config.protected_path_bonus,
            unknown_process_bonus: config.unknown_process_bonus,
            bytes_per_score: config.bytes_per_score.max(1),
        }
    }

    fn classify_level(&self, score: u32) -> BehaviorLevel {
        if score >= self.fuse_score {
            BehaviorLevel::FuseCandidate
        } else if score >= self.throttle_score {
            BehaviorLevel::ThrottleCandidate
        } else if score >= self.suspicious_score {
            BehaviorLevel::Suspicious
        } else {
            BehaviorLevel::Observed
        }
    }

    fn should_add_unknown_process_bonus(
        &self,
        batch: &FileActivityBatch,
        throughput_score: u32,
        correlation: &CorrelationResult,
    ) -> bool {
        correlation.process.is_none()
            && !batch.file_ops.is_empty()
            && (batch.file_ops.renamed > 0
                || batch.file_ops.deleted > 0
                || !batch.protected_paths_touched.is_empty()
                || throughput_score > 0)
    }

    fn context_adjustment(
        &self,
        batch: &FileActivityBatch,
        process: Option<&ProcessInfo>,
        components: ScoreComponents,
    ) -> ScoreAdjustment {
        let Some(process) = process else {
            return ScoreAdjustment::default();
        };

        let mut adjustment = ScoreAdjustment::default();
        let known_java_temp_extraction = is_known_java_temp_extraction(process, batch);
        let package_manager_helper_activity = is_package_manager_helper_activity(process, batch);
        let trusted_maintenance_activity = is_trusted_maintenance_activity(process, batch);
        let containerized_service_temp_activity =
            is_containerized_service_temp_activity(process, batch);
        let agent_internal_activity = is_agent_internal_activity(process, batch);
        let process_name_mismatch = has_process_name_mismatch(process);
        let suppress_rename = package_manager_helper_activity
            || trusted_maintenance_activity
            || containerized_service_temp_activity
            || agent_internal_activity;
        let suppress_write = known_java_temp_extraction
            || package_manager_helper_activity
            || trusted_maintenance_activity
            || containerized_service_temp_activity;
        let suppress_delete = known_java_temp_extraction
            || package_manager_helper_activity
            || trusted_maintenance_activity
            || containerized_service_temp_activity
            || agent_internal_activity;
        let suppress_throughput = known_java_temp_extraction
            || package_manager_helper_activity
            || trusted_maintenance_activity
            || containerized_service_temp_activity;
        let suppress_protected_path = trusted_maintenance_activity || agent_internal_activity;

        if suppress_rename {
            adjustment.penalty = adjustment.penalty.saturating_add(components.rename);
        }

        if suppress_write {
            adjustment.penalty = adjustment.penalty.saturating_add(components.write);
        }

        if suppress_delete {
            adjustment.penalty = adjustment.penalty.saturating_add(components.delete);
        }

        if suppress_throughput {
            adjustment.penalty = adjustment.penalty.saturating_add(components.throughput);
        }

        if suppress_protected_path {
            adjustment.penalty = adjustment.penalty.saturating_add(components.protected_path);
        }

        if known_java_temp_extraction {
            adjustment
                .reasons
                .push("known JVM temp extraction pattern".to_string());
        }

        if package_manager_helper_activity {
            adjustment
                .reasons
                .push("package-manager helper activity".to_string());
        }

        if trusted_maintenance_activity {
            adjustment
                .reasons
                .push("trusted maintenance activity".to_string());
        }

        if containerized_service_temp_activity {
            adjustment
                .reasons
                .push("containerized service temp activity".to_string());
        }

        if agent_internal_activity {
            adjustment
                .reasons
                .push("agent internal activity".to_string());
        }

        if is_temp_path(&process.exe_path)
            && !known_java_temp_extraction
            && !package_manager_helper_activity
            && !trusted_maintenance_activity
            && !containerized_service_temp_activity
            && !agent_internal_activity
        {
            adjustment.bonus = adjustment
                .bonus
                .saturating_add(self.protected_path_bonus)
                .saturating_add(self.unknown_process_bonus);
            adjustment.reasons.push("temp-path executable".to_string());
        }

        if process_name_mismatch {
            adjustment.bonus = adjustment.bonus.saturating_add(self.protected_path_bonus);
            adjustment
                .reasons
                .push("process name/executable mismatch".to_string());
        }

        adjustment
    }

    pub fn score_temp_exec_trigger(
        &self,
        timestamp: DateTime<Utc>,
        source: &str,
        watched_root: &str,
        matched_path: &str,
        process: Option<&ProcessInfo>,
    ) -> BehaviorEvent {
        let mut score = self.suspicious_score;
        let mut reasons = vec![
            "temp write followed by execve".to_string(),
            "temp-path executable".to_string(),
        ];

        if let Some(process) = process {
            if has_process_name_mismatch(process) {
                score = score.saturating_add(self.protected_path_bonus);
                reasons.push("process name/executable mismatch".to_string());
            }
        }

        BehaviorEvent {
            timestamp,
            source: source.to_string(),
            watched_root: watched_root.to_string(),
            pid: process.map(|proc_info| proc_info.pid),
            parent_pid: process.and_then(|proc_info| proc_info.parent_pid),
            uid: process.and_then(|proc_info| proc_info.uid),
            gid: process.and_then(|proc_info| proc_info.gid),
            service_unit: process.and_then(|proc_info| proc_info.service_unit.clone()),
            first_seen_at: process.map(|proc_info| proc_info.first_seen_at),
            trust_class: process.map(|proc_info| proc_info.trust_class),
            trust_policy_name: process.and_then(|proc_info| proc_info.trust_policy_name.clone()),
            maintenance_activity: process.and_then(|proc_info| proc_info.maintenance_activity),
            trust_policy_visibility: process
                .map(|proc_info| proc_info.trust_policy_visibility)
                .unwrap_or_default(),
            package_name: process.and_then(|proc_info| proc_info.package_name.clone()),
            package_manager: process.and_then(|proc_info| proc_info.package_manager.clone()),
            process_name: process.map(|proc_info| proc_info.process_name.clone()),
            exe_path: process.map(|proc_info| proc_info.exe_path.clone()),
            command_line: process.map(|proc_info| proc_info.command_line.clone()),
            parent_process_name: process
                .and_then(|proc_info| proc_info.parent_process_name.clone()),
            parent_command_line: process
                .and_then(|proc_info| proc_info.parent_command_line.clone()),
            parent_chain: process
                .map(|proc_info| proc_info.parent_chain.clone())
                .unwrap_or_default(),
            container_runtime: process.and_then(|proc_info| proc_info.container_runtime.clone()),
            container_id: process.and_then(|proc_info| proc_info.container_id.clone()),
            correlation_hits: process
                .map(|proc_info| proc_info.correlation_hits)
                .unwrap_or(0),
            file_ops: FileOperationCounts::default(),
            touched_paths: vec![matched_path.to_string()],
            protected_paths_touched: Vec::new(),
            bytes_written: 0,
            io_rate_bytes_per_sec: 0,
            score,
            reasons,
            level: self.classify_level(score),
        }
    }
}

impl Scorer for CompositeBehaviorScorer {
    fn score(&self, batch: &FileActivityBatch, correlation: &CorrelationResult) -> BehaviorEvent {
        let mut score = 0u32;
        let mut reasons = Vec::new();

        let rename_component = effective_burst_score(
            batch.file_ops.renamed,
            RENAME_BURST_GRACE,
            self.rename_score,
        );
        if batch.file_ops.renamed > 0 {
            score = score.saturating_add(rename_component);
            reasons.push(format!("rename burst x{}", batch.file_ops.renamed));
        }

        let write_component = batch.file_ops.modified.saturating_mul(self.write_score);
        if batch.file_ops.modified > 0 {
            score = score.saturating_add(write_component);
            reasons.push(format!("write burst x{}", batch.file_ops.modified));
        }

        let delete_component = effective_burst_score(
            batch.file_ops.deleted,
            DELETE_BURST_GRACE,
            self.delete_score,
        );
        if batch.file_ops.deleted > 0 {
            score = score.saturating_add(delete_component);
            reasons.push(format!("delete burst x{}", batch.file_ops.deleted));
        }

        let protected_path_component = if batch.protected_paths_touched.is_empty() {
            0
        } else {
            self.protected_path_bonus
        };
        if !batch.protected_paths_touched.is_empty() {
            score = score.saturating_add(protected_path_component);
            reasons.push("protected path touched".to_string());
        }

        let throughput_component =
            (batch.bytes_written / self.bytes_per_score).min(u64::from(u32::MAX)) as u32;

        if self.should_add_unknown_process_bonus(batch, throughput_component, correlation) {
            score = score.saturating_add(self.unknown_process_bonus);
            reasons.push("unknown process activity".to_string());
        }

        if throughput_component > 0 {
            score = score.saturating_add(throughput_component);
            reasons.push(format!(
                "write throughput {}B/s",
                batch.io_rate_bytes_per_sec
            ));
        }

        let process = correlation.process.as_ref();
        let adjustment = self.context_adjustment(
            batch,
            process,
            ScoreComponents {
                protected_path: protected_path_component,
                rename: rename_component,
                write: write_component,
                delete: delete_component,
                throughput: throughput_component,
            },
        );
        score = score
            .saturating_sub(adjustment.penalty)
            .saturating_add(adjustment.bonus);
        reasons.extend(adjustment.reasons);
        let level = self.classify_level(score);

        BehaviorEvent {
            timestamp: batch.timestamp,
            source: batch.source.clone(),
            watched_root: batch.watched_root.clone(),
            pid: process.map(|proc_info| proc_info.pid),
            parent_pid: process.and_then(|proc_info| proc_info.parent_pid),
            uid: process.and_then(|proc_info| proc_info.uid),
            gid: process.and_then(|proc_info| proc_info.gid),
            service_unit: process.and_then(|proc_info| proc_info.service_unit.clone()),
            first_seen_at: process.map(|proc_info| proc_info.first_seen_at),
            trust_class: process.map(|proc_info| proc_info.trust_class),
            trust_policy_name: process.and_then(|proc_info| proc_info.trust_policy_name.clone()),
            maintenance_activity: process.and_then(|proc_info| proc_info.maintenance_activity),
            trust_policy_visibility: process
                .map(|proc_info| proc_info.trust_policy_visibility)
                .unwrap_or_default(),
            package_name: process.and_then(|proc_info| proc_info.package_name.clone()),
            package_manager: process.and_then(|proc_info| proc_info.package_manager.clone()),
            process_name: process.map(|proc_info| proc_info.process_name.clone()),
            exe_path: process.map(|proc_info| proc_info.exe_path.clone()),
            command_line: process.map(|proc_info| proc_info.command_line.clone()),
            parent_process_name: process
                .and_then(|proc_info| proc_info.parent_process_name.clone()),
            parent_command_line: process
                .and_then(|proc_info| proc_info.parent_command_line.clone()),
            parent_chain: process
                .map(|proc_info| proc_info.parent_chain.clone())
                .unwrap_or_default(),
            container_runtime: process.and_then(|proc_info| proc_info.container_runtime.clone()),
            container_id: process.and_then(|proc_info| proc_info.container_id.clone()),
            correlation_hits: process
                .map(|proc_info| proc_info.correlation_hits)
                .unwrap_or(0),
            file_ops: batch.file_ops,
            touched_paths: batch.touched_paths.clone(),
            protected_paths_touched: batch.protected_paths_touched.clone(),
            bytes_written: batch.bytes_written,
            io_rate_bytes_per_sec: batch.io_rate_bytes_per_sec,
            score,
            reasons,
            level,
        }
    }
}

fn is_temp_path(path: &str) -> bool {
    let trimmed = path.trim();
    TEMP_ROOTS
        .iter()
        .any(|root| trimmed == *root || trimmed.starts_with(&format!("{root}/")))
}

fn batch_touches_only_temp_paths(batch: &FileActivityBatch) -> bool {
    let mut saw_path = false;

    for path in batch
        .touched_paths
        .iter()
        .chain(batch.protected_paths_touched.iter())
    {
        saw_path = true;
        if !is_temp_path(path) {
            return false;
        }
    }

    if saw_path {
        true
    } else {
        is_temp_path(&batch.watched_root)
    }
}

fn batch_touches_only_paths(batch: &FileActivityBatch, prefixes: &[&str]) -> bool {
    let mut saw_path = false;

    for path in batch
        .touched_paths
        .iter()
        .chain(batch.protected_paths_touched.iter())
    {
        saw_path = true;
        if !path_matches_any_prefix(path, prefixes) {
            return false;
        }
    }

    if saw_path {
        true
    } else {
        path_matches_any_prefix(&batch.watched_root, prefixes)
    }
}

fn process_matches_any_command_name(process: &ProcessInfo, patterns: &[&str]) -> bool {
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

fn process_matches_any_runtime_marker(process: &ProcessInfo, patterns: &[&str]) -> bool {
    let terms = process_runtime_terms(process);
    patterns.iter().any(|pattern| {
        let normalized = pattern.trim().to_ascii_lowercase();
        !normalized.is_empty() && terms.contains(&normalized)
    })
}

fn is_known_java_temp_extraction(process: &ProcessInfo, batch: &FileActivityBatch) -> bool {
    batch_touches_only_temp_paths(batch)
        && batch.file_ops.modified > 0
        && batch.file_ops.deleted > 0
        && process_matches_any_command_name(process, &["java"])
        && process_matches_any_runtime_marker(process, KNOWN_JAVA_RUNTIME_MARKERS)
}

fn is_package_manager_helper_activity(process: &ProcessInfo, batch: &FileActivityBatch) -> bool {
    batch_touches_only_temp_paths(batch)
        && matches!(
            process.maintenance_activity,
            Some(MaintenanceActivity::PackageManagerHelper)
        )
}

fn is_trusted_maintenance_activity(process: &ProcessInfo, batch: &FileActivityBatch) -> bool {
    batch_touches_only_paths(batch, MAINTENANCE_PATH_PREFIXES)
        && matches!(
            process.maintenance_activity,
            Some(MaintenanceActivity::TrustedMaintenance)
        )
}

fn is_agent_internal_activity(process: &ProcessInfo, batch: &FileActivityBatch) -> bool {
    process_matches_any_command_name(process, AGENT_INTERNAL_PATTERNS)
        || batch_touches_only_paths(batch, AGENT_INTERNAL_PATH_PREFIXES)
}

fn is_containerized_service_temp_activity(
    process: &ProcessInfo,
    batch: &FileActivityBatch,
) -> bool {
    batch_touches_only_temp_paths(batch)
        && process.container_id.is_some()
        && process.container_runtime.is_some()
        && is_trusted_system_executable(&process.exe_path)
        && !is_temp_path(&process.exe_path)
        && !has_shell_like_parent(process)
}

fn has_shell_like_parent(process: &ProcessInfo) -> bool {
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

fn is_trusted_system_executable(path: &str) -> bool {
    TRUSTED_EXEC_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

fn path_matches_any_prefix(path: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| {
        if *prefix == "/.config/bannkenn" {
            path.contains(prefix)
        } else {
            path == *prefix || path.starts_with(&format!("{prefix}/"))
        }
    })
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

fn process_runtime_terms(process: &ProcessInfo) -> HashSet<String> {
    let mut terms = HashSet::new();
    extend_runtime_terms(&mut terms, &process.process_name);
    extend_runtime_terms(&mut terms, &process.exe_path);
    extend_runtime_terms(&mut terms, &process.command_line);
    terms
}

fn extend_runtime_terms(terms: &mut HashSet<String>, value: &str) {
    if value.trim().is_empty() {
        return;
    }

    terms.insert(value.trim().to_ascii_lowercase());

    if let Some(basename) = path_basename(value) {
        terms.insert(basename.to_ascii_lowercase());
    }

    for token in value.split_whitespace() {
        let lower = token.to_ascii_lowercase();
        if lower.is_empty() {
            continue;
        }

        terms.insert(lower.clone());

        if let Some(basename) = path_basename(token) {
            terms.insert(basename.to_ascii_lowercase());
        }

        for component in token.split('/') {
            let lower = component.to_ascii_lowercase();
            if !lower.is_empty() {
                terms.insert(lower);
            }
        }

        for segment in token.split(|ch: char| !ch.is_ascii_alphanumeric()) {
            let lower = segment.to_ascii_lowercase();
            if !lower.is_empty() {
                terms.insert(lower);
            }
        }
    }
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

fn normalize_command_name(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn has_process_name_mismatch(process: &ProcessInfo) -> bool {
    let process_name = normalize_process_name(&process.process_name);
    let exe_name = Path::new(&process.exe_path)
        .file_name()
        .and_then(|name| name.to_str())
        .map(normalize_process_name)
        .unwrap_or_default();

    if process_name.is_empty() || exe_name.is_empty() {
        return false;
    }

    process_name != exe_name
        && !process_name.contains(&exe_name)
        && !exe_name.contains(&process_name)
}

fn normalize_process_name(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn effective_burst_score(count: u32, grace: u32, score_per_event: u32) -> u32 {
    count.saturating_sub(grace).saturating_mul(score_per_event)
}

#[cfg(test)]
#[path = "../tests/unit/scorer_tests.rs"]
mod tests;
