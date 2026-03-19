use crate::config::ContainmentConfig;
use crate::correlator::CorrelationResult;
use crate::ebpf::events::{BehaviorEvent, BehaviorLevel, FileActivityBatch, ProcessInfo};

const TEMP_ROOTS: &[&str] = &["/tmp", "/var/tmp"];
const PACKAGE_HELPER_PATTERNS: &[&str] = &[
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
const KNOWN_JAVA_RUNTIME_MARKERS: &[&str] =
    &["opensearch", "wazuh-indexer", "org.opensearch", "solr"];
const SHELL_LIKE_PARENT_PATTERNS: &[&str] = &["sh", "bash", "dash", "zsh", "ash", "busybox"];
const TRUSTED_EXEC_PREFIXES: &[&str] = &["/usr/", "/bin/", "/sbin/", "/lib/", "/nix/store/"];

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ScoreAdjustment {
    penalty: u32,
    bonus: u32,
    reasons: Vec<String>,
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
        rename_component: u32,
        write_component: u32,
        delete_component: u32,
        throughput_component: u32,
    ) -> ScoreAdjustment {
        let Some(process) = process else {
            return ScoreAdjustment::default();
        };

        let mut adjustment = ScoreAdjustment::default();
        let known_java_temp_extraction = is_known_java_temp_extraction(process, batch);
        let package_manager_helper_activity = is_package_manager_helper_activity(process, batch);
        let containerized_service_temp_activity =
            is_containerized_service_temp_activity(process, batch);

        if known_java_temp_extraction {
            adjustment.penalty = adjustment
                .penalty
                .saturating_add(write_component.saturating_add(delete_component))
                .saturating_add(throughput_component);
            adjustment
                .reasons
                .push("known JVM temp extraction pattern".to_string());
        }

        if package_manager_helper_activity {
            adjustment.penalty = adjustment
                .penalty
                .saturating_add(rename_component)
                .saturating_add(write_component)
                .saturating_add(delete_component)
                .saturating_add(throughput_component);
            adjustment
                .reasons
                .push("package-manager helper activity".to_string());
        }

        if containerized_service_temp_activity {
            adjustment.penalty = adjustment
                .penalty
                .saturating_add(rename_component)
                .saturating_add(write_component)
                .saturating_add(delete_component)
                .saturating_add(throughput_component);
            adjustment
                .reasons
                .push("containerized service temp activity".to_string());
        }

        if is_temp_path(&process.exe_path)
            && !known_java_temp_extraction
            && !package_manager_helper_activity
            && !containerized_service_temp_activity
        {
            adjustment.bonus = adjustment
                .bonus
                .saturating_add(self.protected_path_bonus)
                .saturating_add(self.unknown_process_bonus);
            adjustment.reasons.push("temp-path executable".to_string());
        }

        adjustment
    }
}

impl Scorer for CompositeBehaviorScorer {
    fn score(&self, batch: &FileActivityBatch, correlation: &CorrelationResult) -> BehaviorEvent {
        let mut score = 0u32;
        let mut reasons = Vec::new();

        let rename_component = batch.file_ops.renamed.saturating_mul(self.rename_score);
        if batch.file_ops.renamed > 0 {
            score = score.saturating_add(rename_component);
            reasons.push(format!("rename burst x{}", batch.file_ops.renamed));
        }

        let write_component = batch.file_ops.modified.saturating_mul(self.write_score);
        if batch.file_ops.modified > 0 {
            score = score.saturating_add(write_component);
            reasons.push(format!("write burst x{}", batch.file_ops.modified));
        }

        let delete_component = batch.file_ops.deleted.saturating_mul(self.delete_score);
        if batch.file_ops.deleted > 0 {
            score = score.saturating_add(delete_component);
            reasons.push(format!("delete burst x{}", batch.file_ops.deleted));
        }

        if !batch.protected_paths_touched.is_empty() {
            score = score.saturating_add(self.protected_path_bonus);
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
            rename_component,
            write_component,
            delete_component,
            throughput_component,
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
            process_name: process.map(|proc_info| proc_info.process_name.clone()),
            exe_path: process.map(|proc_info| proc_info.exe_path.clone()),
            command_line: process.map(|proc_info| proc_info.command_line.clone()),
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

fn process_matches_any_pattern(process: &ProcessInfo, patterns: &[&str]) -> bool {
    let process_name = process.process_name.to_ascii_lowercase();
    let exe_path = process.exe_path.to_ascii_lowercase();
    let command_line = process.command_line.to_ascii_lowercase();

    patterns.iter().any(|pattern| {
        process_name.contains(pattern)
            || exe_path.contains(pattern)
            || command_line.contains(pattern)
    })
}

fn is_known_java_temp_extraction(process: &ProcessInfo, batch: &FileActivityBatch) -> bool {
    batch_touches_only_temp_paths(batch)
        && batch.file_ops.modified > 0
        && batch.file_ops.deleted > 0
        && process_matches_any_pattern(process, &["java"])
        && process_matches_any_pattern(process, KNOWN_JAVA_RUNTIME_MARKERS)
}

fn is_package_manager_helper_activity(process: &ProcessInfo, batch: &FileActivityBatch) -> bool {
    batch_touches_only_temp_paths(batch)
        && process_matches_any_pattern(process, PACKAGE_HELPER_PATTERNS)
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
    process
        .parent_process_name
        .as_deref()
        .map(|name| contains_any_ascii_case_insensitive(name, SHELL_LIKE_PARENT_PATTERNS))
        .unwrap_or(false)
        || process
            .parent_command_line
            .as_deref()
            .map(|cmd| contains_any_ascii_case_insensitive(cmd, SHELL_LIKE_PARENT_PATTERNS))
            .unwrap_or(false)
}

fn is_trusted_system_executable(path: &str) -> bool {
    TRUSTED_EXEC_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

fn contains_any_ascii_case_insensitive(value: &str, patterns: &[&str]) -> bool {
    let lower = value.to_ascii_lowercase();
    patterns.iter().any(|pattern| lower.contains(pattern))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ContainmentConfig;
    use crate::ebpf::events::{FileActivityBatch, FileOperationCounts, ProcessInfo};
    use chrono::Utc;

    fn batch_with_ops(
        file_ops: FileOperationCounts,
        touched_paths: Vec<&str>,
        bytes_written: u64,
    ) -> FileActivityBatch {
        FileActivityBatch {
            timestamp: Utc::now(),
            source: "userspace_polling".to_string(),
            watched_root: "/tmp".to_string(),
            poll_interval_ms: 1000,
            file_ops,
            touched_paths: touched_paths.into_iter().map(str::to_string).collect(),
            protected_paths_touched: Vec::new(),
            bytes_written,
            io_rate_bytes_per_sec: bytes_written,
        }
    }

    fn process(pid: u32, process_name: &str, exe_path: &str, command_line: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            process_name: process_name.to_string(),
            exe_path: exe_path.to_string(),
            command_line: command_line.to_string(),
            correlation_hits: 20,
            parent_process_name: None,
            parent_command_line: None,
            container_runtime: None,
            container_id: None,
        }
    }

    #[test]
    fn mass_rename_scores_as_suspicious() {
        let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
        let batch = FileActivityBatch {
            timestamp: Utc::now(),
            source: "userspace_polling".to_string(),
            watched_root: "/srv/data".to_string(),
            poll_interval_ms: 1000,
            file_ops: FileOperationCounts {
                renamed: 7,
                ..Default::default()
            },
            touched_paths: vec!["/srv/data/a".to_string()],
            protected_paths_touched: Vec::new(),
            bytes_written: 0,
            io_rate_bytes_per_sec: 0,
        };
        let correlation = CorrelationResult {
            process: Some(ProcessInfo {
                pid: 4242,
                process_name: "python3".to_string(),
                exe_path: "/usr/bin/python3".to_string(),
                command_line: "python3 encrypt.py".to_string(),
                correlation_hits: 20,
                parent_process_name: Some("systemd".to_string()),
                parent_command_line: Some("systemd".to_string()),
                container_runtime: None,
                container_id: None,
            }),
            protected_hits: 0,
        };

        let event = scorer.score(&batch, &correlation);
        assert_eq!(event.level, BehaviorLevel::Suspicious);
        assert!(event.score > 30);
    }

    #[test]
    fn unknown_process_write_only_no_longer_crosses_suspicious_threshold_by_itself() {
        let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
        let batch = batch_with_ops(
            FileOperationCounts {
                modified: 8,
                ..Default::default()
            },
            vec!["/tmp/write-only.tmp"],
            0,
        );
        let correlation = CorrelationResult::default();

        let event = scorer.score(&batch, &correlation);

        assert_eq!(event.level, BehaviorLevel::Observed);
        assert!(!event
            .reasons
            .iter()
            .any(|reason| reason == "unknown process activity"));
    }

    #[test]
    fn known_java_temp_extraction_is_downgraded() {
        let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
        let batch = batch_with_ops(
            FileOperationCounts {
                modified: 5,
                deleted: 5,
                ..Default::default()
            },
            vec!["/tmp/opensearch-123/libzstd-jni.so"],
            2 * 1_048_576,
        );
        let correlation = CorrelationResult {
            process: Some(process(
                4242,
                "java",
                "/usr/share/wazuh-indexer/jdk/bin/java",
                "/usr/share/wazuh-indexer/jdk/bin/java -Djava.io.tmpdir=/tmp/opensearch-123 -cp /usr/share/wazuh-indexer/lib/* org.opensearch.bootstrap.OpenSearch",
            )),
            protected_hits: 0,
        };

        let event = scorer.score(&batch, &correlation);

        assert_eq!(event.level, BehaviorLevel::Observed);
        assert!(event
            .reasons
            .iter()
            .any(|reason| reason == "known JVM temp extraction pattern"));
    }

    #[test]
    fn package_manager_helper_temp_activity_is_downgraded() {
        let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
        let batch = batch_with_ops(
            FileOperationCounts {
                modified: 10,
                ..Default::default()
            },
            vec!["/var/tmp/dpkg-unpack"],
            3 * 1_048_576,
        );
        let correlation = CorrelationResult {
            process: Some(process(
                84,
                "depmod",
                "/usr/sbin/depmod",
                "/usr/sbin/depmod -a",
            )),
            protected_hits: 0,
        };

        let event = scorer.score(&batch, &correlation);

        assert_eq!(event.level, BehaviorLevel::Observed);
        assert!(event
            .reasons
            .iter()
            .any(|reason| reason == "package-manager helper activity"));
    }

    #[test]
    fn trusted_containerized_service_temp_activity_is_downgraded() {
        let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
        let batch = batch_with_ops(
            FileOperationCounts {
                modified: 5,
                deleted: 5,
                ..Default::default()
            },
            vec!["/tmp/#sql-temptable"],
            2 * 1_048_576,
        );
        let mut proc = process(
            55,
            "mariadbd",
            "/usr/sbin/mariadbd",
            "mariadbd --user=node --datadir=/app/data/mariadb --socket=/app/data/run/mariadb.sock",
        );
        proc.parent_process_name = Some("node".to_string());
        proc.parent_command_line = Some("node server/server.js".to_string());
        proc.container_runtime = Some("docker".to_string());
        proc.container_id = Some("0123456789abcdef0123456789abcdef".to_string());
        let correlation = CorrelationResult {
            process: Some(proc),
            protected_hits: 0,
        };

        let event = scorer.score(&batch, &correlation);

        assert_eq!(event.level, BehaviorLevel::Observed);
        assert!(event
            .reasons
            .iter()
            .any(|reason| reason == "containerized service temp activity"));
    }

    #[test]
    fn temp_path_executable_gets_extra_suspicion() {
        let scorer = CompositeBehaviorScorer::from_config(&ContainmentConfig::default());
        let batch = batch_with_ops(
            FileOperationCounts {
                modified: 3,
                deleted: 2,
                ..Default::default()
            },
            vec!["/tmp/ransom/payload"],
            0,
        );
        let correlation = CorrelationResult {
            process: Some(process(
                99,
                "ransom",
                "/tmp/ransom/payload",
                "/tmp/ransom/payload --encrypt /srv/data",
            )),
            protected_hits: 0,
        };

        let event = scorer.score(&batch, &correlation);

        assert_eq!(event.level, BehaviorLevel::Suspicious);
        assert!(event
            .reasons
            .iter()
            .any(|reason| reason == "temp-path executable"));
        assert!(event.score >= 30);
    }
}
