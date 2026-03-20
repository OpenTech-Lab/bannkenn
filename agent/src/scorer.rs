use crate::config::ContainmentConfig;
use crate::correlator::CorrelationResult;
use crate::ebpf::events::{
    BehaviorEvent, BehaviorLevel, FileActivityBatch, FileOperationCounts, MaintenanceActivity,
    ProcessInfo, ProcessTrustClass,
};
use chrono::{DateTime, Utc};
use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
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
const USER_DATA_PATH_PREFIXES: &[&str] = &[
    "/home", "/srv", "/var/www", "/var/lib", "/opt", "/data", "/mnt", "/media",
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
const BENIGN_RENAME_EXTENSION_TARGETS: &[&str] = &[
    "tmp", "temp", "bak", "backup", "old", "new", "part", "partial", "swp", "swx", "dpkg-new",
    "dpkg-old", "rpmnew", "rpmsave", "pacnew", "pacsave",
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
    directory_spread: u32,
    high_entropy_rewrite: u32,
    unreadable_rewrite: u32,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct BehaviorChainInputs {
    extension_anomaly_component: u32,
    high_entropy_rewrite_component: u32,
    unreadable_rewrite_component: u32,
    user_data_component: u32,
    directory_spread_component: u32,
    throughput_component: u32,
    recurrence_component: u32,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ContextFlags {
    known_java_temp_extraction: bool,
    package_manager_helper_activity: bool,
    trusted_maintenance_activity: bool,
    containerized_service_temp_activity: bool,
    agent_internal_activity: bool,
    process_name_mismatch: bool,
    shell_like_parent: bool,
    temp_path_executable: bool,
}

impl ContextFlags {
    fn maintenance_context(self) -> bool {
        self.known_java_temp_extraction
            || self.package_manager_helper_activity
            || self.trusted_maintenance_activity
            || self.containerized_service_temp_activity
            || self.agent_internal_activity
    }

    fn suspicious_lineage(self) -> bool {
        self.process_name_mismatch || self.shell_like_parent || self.temp_path_executable
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct BehaviorChainAssessment {
    signal_count: u32,
    weak_identity: bool,
    meaningful_rename: bool,
    extension_anomaly: bool,
    high_entropy_rewrite: bool,
    unreadable_rewrite: bool,
    repeated_writes: bool,
    user_data_targeting: bool,
    suspicious_lineage: bool,
    directory_spread: bool,
    rapid_delete: bool,
    recurrence_history: bool,
    maintenance_context: bool,
    signal_names: Vec<&'static str>,
}

impl BehaviorChainAssessment {
    fn qualifies_for_high_risk(&self, min_signals: u32) -> bool {
        !self.maintenance_context
            && self.signal_count >= min_signals
            && self.weak_identity
            && self.repeated_writes
            && self.user_data_targeting
            && (self.meaningful_rename
                || self.extension_anomaly
                || self.high_entropy_rewrite
                || self.unreadable_rewrite
                || self.recurrence_history)
    }

    fn qualifies_for_containment_candidate(
        &self,
        high_risk_min_signals: u32,
        containment_candidate_min_signals: u32,
    ) -> bool {
        self.qualifies_for_high_risk(high_risk_min_signals)
            && self.signal_count >= containment_candidate_min_signals
            && (self.meaningful_rename
                || self.extension_anomaly
                || self.high_entropy_rewrite
                || self.unreadable_rewrite)
            && (self.suspicious_lineage
                || self.directory_spread
                || self.rapid_delete
                || self.recurrence_history)
    }

    fn summary_reason(&self) -> Option<String> {
        (!self.signal_names.is_empty())
            .then(|| format!("behavior chain signals: {}", self.signal_names.join(", ")))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecentBehaviorObservation {
    timestamp: DateTime<Utc>,
    watched_root: String,
    process_identity: Option<String>,
    dominant_extension: Option<String>,
    weak_identity: bool,
    user_data_targeting: bool,
    suspicious_lineage: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservationContext {
    dominant_extension: Option<String>,
    weak_identity: bool,
    user_data_targeting: bool,
    suspicious_lineage: bool,
    score: u32,
}

pub trait Scorer {
    fn score(&self, batch: &FileActivityBatch, correlation: &CorrelationResult) -> BehaviorEvent;
}

#[derive(Debug, Clone)]
pub struct CompositeBehaviorScorer {
    suspicious_score: u32,
    high_risk_score: u32,
    containment_candidate_score: u32,
    rename_score: u32,
    write_score: u32,
    delete_score: u32,
    high_entropy_rewrite_score: u32,
    unreadable_rewrite_score: u32,
    extension_anomaly_score: u32,
    extension_anomaly_min_count: u32,
    protected_path_bonus: u32,
    user_data_bonus: u32,
    unknown_process_bonus: u32,
    trusted_process_penalty: u32,
    allowed_local_penalty: u32,
    directory_spread_score: u32,
    shell_parent_bonus: u32,
    recent_process_bonus: u32,
    recent_process_window_secs: u64,
    meaningful_rename_count: u32,
    meaningful_write_count: u32,
    high_risk_min_signals: u32,
    containment_candidate_min_signals: u32,
    recurrence_score: u32,
    recurrence_window_secs: u64,
    recurrence_min_events: u32,
    bytes_per_score: u64,
    recent_observations: RefCell<VecDeque<RecentBehaviorObservation>>,
}

impl CompositeBehaviorScorer {
    pub fn from_config(config: &ContainmentConfig) -> Self {
        let suspicious_score =
            adjust_threshold_for_profile(config.suspicious_score, config.environment_profile, 5);
        let high_risk_score =
            adjust_threshold_for_profile(config.throttle_score, config.environment_profile, 10);
        let containment_candidate_score =
            adjust_threshold_for_profile(config.fuse_score, config.environment_profile, 10);
        let high_risk_min_signals = adjust_signal_requirement_for_profile(
            config.high_risk_min_signals.max(1),
            config.environment_profile,
        );
        let containment_candidate_min_signals = adjust_signal_requirement_for_profile(
            config
                .containment_candidate_min_signals
                .max(config.high_risk_min_signals.max(1)),
            config.environment_profile,
        )
        .max(high_risk_min_signals);

        Self {
            suspicious_score,
            high_risk_score,
            containment_candidate_score,
            rename_score: config.rename_score,
            write_score: config.write_score,
            delete_score: config.delete_score,
            high_entropy_rewrite_score: config.high_entropy_rewrite_score,
            unreadable_rewrite_score: config.unreadable_rewrite_score,
            extension_anomaly_score: config.extension_anomaly_score,
            extension_anomaly_min_count: config.extension_anomaly_min_count.max(1),
            protected_path_bonus: config.protected_path_bonus,
            user_data_bonus: config.user_data_bonus,
            unknown_process_bonus: config.unknown_process_bonus,
            trusted_process_penalty: config.trusted_process_penalty,
            allowed_local_penalty: config.allowed_local_penalty,
            directory_spread_score: config.directory_spread_score,
            shell_parent_bonus: config.shell_parent_bonus,
            recent_process_bonus: config.recent_process_bonus,
            recent_process_window_secs: config.recent_process_window_secs,
            meaningful_rename_count: config.meaningful_rename_count.max(RENAME_BURST_GRACE + 1),
            meaningful_write_count: config.meaningful_write_count.max(1),
            high_risk_min_signals,
            containment_candidate_min_signals,
            recurrence_score: config.recurrence_score,
            recurrence_window_secs: config.recurrence_window_secs.max(1),
            recurrence_min_events: config.recurrence_min_events.max(2),
            bytes_per_score: config.bytes_per_score.max(1),
            recent_observations: RefCell::new(VecDeque::new()),
        }
    }

    fn classify_level(&self, score: u32) -> BehaviorLevel {
        if score >= self.containment_candidate_score {
            BehaviorLevel::ContainmentCandidate
        } else if score >= self.high_risk_score {
            BehaviorLevel::HighRisk
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

    fn protected_path_component(&self, batch: &FileActivityBatch) -> Option<(u32, String)> {
        if !batch.protected_paths_touched.is_empty() {
            return Some((
                self.protected_path_bonus,
                "protected path touched".to_string(),
            ));
        }
        None
    }

    fn user_data_component(
        &self,
        batch: &FileActivityBatch,
        activity_score: u32,
    ) -> Option<(u32, String)> {
        if activity_score == 0 || !batch_targets_user_data(batch) {
            return None;
        }

        Some((
            self.user_data_bonus,
            "user/application data targeted".to_string(),
        ))
    }

    fn directory_spread_component(
        &self,
        batch: &FileActivityBatch,
        activity_score: u32,
    ) -> Option<(u32, String)> {
        if activity_score == 0 {
            return None;
        }

        let directory_count = distinct_parent_dir_count(batch);
        let extra_directories = directory_count.saturating_sub(2).min(4);
        if extra_directories == 0 {
            return None;
        }

        Some((
            extra_directories.saturating_mul(self.directory_spread_score),
            format!("directory spread x{}", directory_count),
        ))
    }

    fn high_entropy_rewrite_component(
        &self,
        batch: &FileActivityBatch,
        activity_score: u32,
    ) -> Option<(u32, String)> {
        if activity_score == 0 || batch.content_indicators.high_entropy_rewrites == 0 {
            return None;
        }

        let count = batch.content_indicators.high_entropy_rewrites;
        Some((
            count.saturating_mul(self.high_entropy_rewrite_score),
            format!("high-entropy rewrite x{}", count),
        ))
    }

    fn unreadable_rewrite_component(
        &self,
        batch: &FileActivityBatch,
        activity_score: u32,
    ) -> Option<(u32, String)> {
        if activity_score == 0 || batch.content_indicators.unreadable_rewrites == 0 {
            return None;
        }

        let count = batch.content_indicators.unreadable_rewrites;
        Some((
            count.saturating_mul(self.unreadable_rewrite_score),
            format!("unreadable rewrite x{}", count),
        ))
    }

    fn extension_anomaly_component(
        &self,
        batch: &FileActivityBatch,
        activity_score: u32,
    ) -> Option<(u32, String, String)> {
        if activity_score == 0 {
            return None;
        }

        let (extension, count) = dominant_rename_extension(batch)?;
        if count < self.extension_anomaly_min_count
            || BENIGN_RENAME_EXTENSION_TARGETS.contains(&extension.as_str())
        {
            return None;
        }

        Some((
            count.saturating_mul(self.extension_anomaly_score),
            format!("rename extension anomaly .{} x{}", extension, count),
            extension,
        ))
    }

    fn trust_adjustment(
        &self,
        batch: &FileActivityBatch,
        process: Option<&ProcessInfo>,
        identity_bonus_signal: bool,
        activity_score: u32,
    ) -> ScoreAdjustment {
        let mut adjustment = ScoreAdjustment::default();

        let Some(process) = process else {
            if identity_bonus_signal {
                adjustment.bonus = adjustment.bonus.saturating_add(self.unknown_process_bonus);
                adjustment
                    .reasons
                    .push("unknown process activity".to_string());
            }
            return adjustment;
        };

        if identity_bonus_signal {
            match process.trust_class {
                crate::ebpf::events::ProcessTrustClass::Unknown => {
                    adjustment.bonus = adjustment.bonus.saturating_add(self.unknown_process_bonus);
                    adjustment
                        .reasons
                        .push("unknown process identity".to_string());
                }
                crate::ebpf::events::ProcessTrustClass::Suspicious => {
                    adjustment.bonus = adjustment
                        .bonus
                        .saturating_add(self.unknown_process_bonus)
                        .saturating_add(self.protected_path_bonus / 2);
                    adjustment
                        .reasons
                        .push("suspicious process identity".to_string());
                }
                _ => {}
            }
        }

        if activity_score > 0 {
            match process.trust_class {
                crate::ebpf::events::ProcessTrustClass::TrustedSystem
                | crate::ebpf::events::ProcessTrustClass::TrustedPackageManaged => {
                    adjustment.penalty = adjustment
                        .penalty
                        .saturating_add(self.trusted_process_penalty);
                    adjustment
                        .reasons
                        .push("trusted process lineage".to_string());
                }
                crate::ebpf::events::ProcessTrustClass::AllowedLocal => {
                    if !identity_bonus_signal {
                        adjustment.penalty = adjustment
                            .penalty
                            .saturating_add(self.allowed_local_penalty);
                        adjustment.reasons.push("allowed local lineage".to_string());
                    }
                }
                _ => {}
            }
        }

        if identity_bonus_signal
            && activity_score > 0
            && matches!(
                process.trust_class,
                crate::ebpf::events::ProcessTrustClass::Unknown
                    | crate::ebpf::events::ProcessTrustClass::Suspicious
            )
            && is_recent_process(process, batch.timestamp, self.recent_process_window_secs)
        {
            adjustment.bonus = adjustment.bonus.saturating_add(self.recent_process_bonus);
            adjustment
                .reasons
                .push("newly observed process".to_string());
        }

        adjustment
    }

    fn assess_behavior_chain(
        &self,
        batch: &FileActivityBatch,
        process: Option<&ProcessInfo>,
        flags: ContextFlags,
        inputs: BehaviorChainInputs,
    ) -> BehaviorChainAssessment {
        let weak_identity = process.is_none_or(|process| {
            matches!(
                process.trust_class,
                ProcessTrustClass::Unknown | ProcessTrustClass::Suspicious
            )
        });
        let meaningful_rename = batch.file_ops.renamed >= self.meaningful_rename_count;
        let extension_anomaly = inputs.extension_anomaly_component > 0;
        let high_entropy_rewrite = inputs.high_entropy_rewrite_component > 0;
        let unreadable_rewrite = inputs.unreadable_rewrite_component > 0;
        let repeated_writes = batch.file_ops.modified >= self.meaningful_write_count
            || inputs.throughput_component > 0;
        let user_data_targeting = inputs.user_data_component > 0;
        let suspicious_lineage = flags.suspicious_lineage();
        let directory_spread = inputs.directory_spread_component > 0;
        let rapid_delete = batch.file_ops.deleted > DELETE_BURST_GRACE;
        let recurrence_history = inputs.recurrence_component > 0;
        let maintenance_context = flags.maintenance_context();
        let mut signal_names = Vec::new();

        if weak_identity {
            signal_names.push("weak_identity");
        }
        if meaningful_rename {
            signal_names.push("meaningful_rename");
        }
        if extension_anomaly {
            signal_names.push("extension_anomaly");
        }
        if high_entropy_rewrite {
            signal_names.push("high_entropy_rewrite");
        }
        if unreadable_rewrite {
            signal_names.push("unreadable_rewrite");
        }
        if repeated_writes {
            signal_names.push("repeated_writes");
        }
        if user_data_targeting {
            signal_names.push("user_data_targeting");
        }
        if suspicious_lineage {
            signal_names.push("suspicious_lineage");
        }
        if directory_spread {
            signal_names.push("directory_spread");
        }
        if rapid_delete {
            signal_names.push("rapid_delete");
        }
        if recurrence_history {
            signal_names.push("recurrence_history");
        }

        BehaviorChainAssessment {
            signal_count: signal_names.len().min(u32::MAX as usize) as u32,
            weak_identity,
            meaningful_rename,
            extension_anomaly,
            high_entropy_rewrite,
            unreadable_rewrite,
            repeated_writes,
            user_data_targeting,
            suspicious_lineage,
            directory_spread,
            rapid_delete,
            recurrence_history,
            maintenance_context,
            signal_names,
        }
    }

    fn correlated_level(
        &self,
        raw_level: BehaviorLevel,
        chain: &BehaviorChainAssessment,
    ) -> (BehaviorLevel, Option<String>) {
        match raw_level {
            BehaviorLevel::ContainmentCandidate => {
                if chain.qualifies_for_containment_candidate(
                    self.high_risk_min_signals,
                    self.containment_candidate_min_signals,
                ) {
                    (BehaviorLevel::ContainmentCandidate, None)
                } else if chain.qualifies_for_high_risk(self.high_risk_min_signals) {
                    (
                        BehaviorLevel::HighRisk,
                        Some(
                            "insufficient correlated ransomware-style signals for containment-candidate escalation"
                                .to_string(),
                        ),
                    )
                } else {
                    (
                        BehaviorLevel::Suspicious,
                        Some(
                            "insufficient correlated ransomware-style signals for high-risk escalation"
                                .to_string(),
                        ),
                    )
                }
            }
            BehaviorLevel::HighRisk => {
                if chain.qualifies_for_high_risk(self.high_risk_min_signals) {
                    (BehaviorLevel::HighRisk, None)
                } else {
                    (
                        BehaviorLevel::Suspicious,
                        Some(
                            "insufficient correlated ransomware-style signals for high-risk escalation"
                                .to_string(),
                        ),
                    )
                }
            }
            level => (level, None),
        }
    }

    fn context_adjustment(
        &self,
        process: Option<&ProcessInfo>,
        components: ScoreComponents,
        flags: ContextFlags,
    ) -> ScoreAdjustment {
        let Some(_process) = process else {
            return ScoreAdjustment::default();
        };

        let mut adjustment = ScoreAdjustment::default();
        let suppress_rename = flags.package_manager_helper_activity
            || flags.trusted_maintenance_activity
            || flags.containerized_service_temp_activity
            || flags.agent_internal_activity;
        let suppress_write = flags.known_java_temp_extraction
            || flags.package_manager_helper_activity
            || flags.trusted_maintenance_activity
            || flags.containerized_service_temp_activity;
        let suppress_delete = flags.known_java_temp_extraction
            || flags.package_manager_helper_activity
            || flags.trusted_maintenance_activity
            || flags.containerized_service_temp_activity
            || flags.agent_internal_activity;
        let suppress_throughput = flags.known_java_temp_extraction
            || flags.package_manager_helper_activity
            || flags.trusted_maintenance_activity
            || flags.containerized_service_temp_activity;
        let suppress_protected_path =
            flags.trusted_maintenance_activity || flags.agent_internal_activity;
        let suppress_directory_spread = flags.known_java_temp_extraction
            || flags.package_manager_helper_activity
            || flags.trusted_maintenance_activity
            || flags.containerized_service_temp_activity
            || flags.agent_internal_activity;
        let suppress_content_rewrite = flags.package_manager_helper_activity
            || flags.trusted_maintenance_activity
            || flags.containerized_service_temp_activity
            || flags.agent_internal_activity;

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

        if suppress_directory_spread {
            adjustment.penalty = adjustment
                .penalty
                .saturating_add(components.directory_spread);
        }

        if suppress_content_rewrite {
            adjustment.penalty = adjustment
                .penalty
                .saturating_add(components.high_entropy_rewrite)
                .saturating_add(components.unreadable_rewrite);
        }

        if flags.known_java_temp_extraction {
            adjustment
                .reasons
                .push("known JVM temp extraction pattern".to_string());
        }

        if flags.package_manager_helper_activity {
            adjustment
                .reasons
                .push("package-manager helper activity".to_string());
        }

        if flags.trusted_maintenance_activity {
            adjustment
                .reasons
                .push("trusted maintenance activity".to_string());
        }

        if flags.containerized_service_temp_activity {
            adjustment
                .reasons
                .push("containerized service temp activity".to_string());
        }

        if flags.agent_internal_activity {
            adjustment
                .reasons
                .push("agent internal activity".to_string());
        }

        if flags.temp_path_executable
            && !flags.known_java_temp_extraction
            && !flags.package_manager_helper_activity
            && !flags.trusted_maintenance_activity
            && !flags.containerized_service_temp_activity
            && !flags.agent_internal_activity
        {
            adjustment.bonus = adjustment
                .bonus
                .saturating_add(self.protected_path_bonus)
                .saturating_add(self.unknown_process_bonus);
            adjustment.reasons.push("temp-path executable".to_string());
        }

        if flags.process_name_mismatch {
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
            container_image: process.and_then(|proc_info| proc_info.container_image.clone()),
            orchestrator: process
                .map(|proc_info| proc_info.orchestrator.clone())
                .unwrap_or_default(),
            container_mounts: process
                .map(|proc_info| proc_info.container_mounts.clone())
                .unwrap_or_default(),
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
        self.prune_recent_observations(batch.timestamp);

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

        let throughput_component =
            (batch.bytes_written / self.bytes_per_score).min(u64::from(u32::MAX)) as u32;
        let pre_path_activity_score = score.saturating_add(throughput_component);
        let (extension_anomaly_component, extension_anomaly_reason, dominant_extension) = self
            .extension_anomaly_component(batch, pre_path_activity_score)
            .map(|(component, reason, extension)| (component, Some(reason), Some(extension)))
            .unwrap_or((0, None, None));
        if extension_anomaly_component > 0 {
            score = score.saturating_add(extension_anomaly_component);
        }
        if let Some(reason) = extension_anomaly_reason {
            reasons.push(reason);
        }

        let (protected_path_component, protected_path_reason) = self
            .protected_path_component(batch)
            .map(|(component, reason)| (component, Some(reason)))
            .unwrap_or((0, None));
        if protected_path_component > 0 {
            score = score.saturating_add(protected_path_component);
        }
        if let Some(reason) = protected_path_reason {
            reasons.push(reason);
        }
        let (user_data_component, user_data_reason) = self
            .user_data_component(batch, pre_path_activity_score)
            .map(|(component, reason)| (component, Some(reason)))
            .unwrap_or((0, None));
        if user_data_component > 0 {
            score = score.saturating_add(user_data_component);
        }
        if let Some(reason) = user_data_reason {
            reasons.push(reason);
        }
        let (high_entropy_rewrite_component, high_entropy_rewrite_reason) = self
            .high_entropy_rewrite_component(batch, pre_path_activity_score)
            .map(|(component, reason)| (component, Some(reason)))
            .unwrap_or((0, None));
        if high_entropy_rewrite_component > 0 {
            score = score.saturating_add(high_entropy_rewrite_component);
        }
        if let Some(reason) = high_entropy_rewrite_reason {
            reasons.push(reason);
        }
        let (unreadable_rewrite_component, unreadable_rewrite_reason) = self
            .unreadable_rewrite_component(batch, pre_path_activity_score)
            .map(|(component, reason)| (component, Some(reason)))
            .unwrap_or((0, None));
        if unreadable_rewrite_component > 0 {
            score = score.saturating_add(unreadable_rewrite_component);
        }
        if let Some(reason) = unreadable_rewrite_reason {
            reasons.push(reason);
        }

        if throughput_component > 0 {
            score = score.saturating_add(throughput_component);
            reasons.push(format!(
                "write throughput {}B/s",
                batch.io_rate_bytes_per_sec
            ));
        }

        let process = correlation.process.as_ref();
        let flags = build_context_flags(batch, process);
        let user_data_targeting = user_data_component > 0;
        let weak_identity = process.is_none_or(|process| {
            matches!(
                process.trust_class,
                ProcessTrustClass::Unknown | ProcessTrustClass::Suspicious
            )
        });
        let recurrence_component = self
            .recurrence_component(
                batch,
                process,
                dominant_extension.as_deref(),
                weak_identity,
                user_data_targeting,
                flags.suspicious_lineage(),
            )
            .map(|(component, reason)| {
                reasons.push(reason);
                component
            })
            .unwrap_or(0);
        if recurrence_component > 0 {
            score = score.saturating_add(recurrence_component);
        }
        let (directory_spread_component, directory_spread_reason) = self
            .directory_spread_component(batch, score)
            .map(|(component, reason)| (component, Some(reason)))
            .unwrap_or((0, None));
        if directory_spread_component > 0 {
            score = score.saturating_add(directory_spread_component);
        }
        if let Some(reason) = directory_spread_reason {
            reasons.push(reason);
        }

        let shell_parent_component = if score > 0 && flags.shell_like_parent {
            self.shell_parent_bonus
        } else {
            0
        };
        if shell_parent_component > 0 {
            score = score.saturating_add(shell_parent_component);
            reasons.push("shell-like parent lineage".to_string());
        }

        let identity_bonus_signal = shell_parent_component > 0
            || self.should_add_unknown_process_bonus(batch, throughput_component, correlation)
            || rename_component > 0
            || delete_component > 0
            || throughput_component > 0
            || extension_anomaly_component > 0
            || high_entropy_rewrite_component > 0
            || unreadable_rewrite_component > 0
            || protected_path_component > 0
            || user_data_component > 0
            || recurrence_component > 0
            || directory_spread_component > 0;
        let behavior_chain = self.assess_behavior_chain(
            batch,
            process,
            flags,
            BehaviorChainInputs {
                extension_anomaly_component,
                high_entropy_rewrite_component,
                unreadable_rewrite_component,
                user_data_component,
                directory_spread_component,
                throughput_component,
                recurrence_component,
            },
        );
        let trust_adjustment = self.trust_adjustment(batch, process, identity_bonus_signal, score);
        let adjustment = self.context_adjustment(
            process,
            ScoreComponents {
                protected_path: protected_path_component,
                rename: rename_component,
                write: write_component,
                delete: delete_component,
                throughput: throughput_component,
                directory_spread: directory_spread_component,
                high_entropy_rewrite: high_entropy_rewrite_component,
                unreadable_rewrite: unreadable_rewrite_component,
            },
            flags,
        );
        score = score
            .saturating_sub(adjustment.penalty)
            .saturating_sub(trust_adjustment.penalty)
            .saturating_add(adjustment.bonus)
            .saturating_add(trust_adjustment.bonus);
        reasons.extend(adjustment.reasons);
        reasons.extend(trust_adjustment.reasons);
        let raw_level = self.classify_level(score);
        let (level, downgrade_reason) = self.correlated_level(raw_level, &behavior_chain);
        if (level != raw_level)
            || matches!(
                level,
                BehaviorLevel::HighRisk | BehaviorLevel::ContainmentCandidate
            )
        {
            if let Some(reason) = behavior_chain.summary_reason() {
                reasons.push(reason);
            }
        }
        if let Some(reason) = downgrade_reason {
            reasons.push(reason);
        }

        let event = BehaviorEvent {
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
            container_image: process.and_then(|proc_info| proc_info.container_image.clone()),
            orchestrator: process
                .map(|proc_info| proc_info.orchestrator.clone())
                .unwrap_or_default(),
            container_mounts: process
                .map(|proc_info| proc_info.container_mounts.clone())
                .unwrap_or_default(),
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
        };

        self.remember_observation(
            batch,
            process,
            ObservationContext {
                dominant_extension,
                weak_identity,
                user_data_targeting,
                suspicious_lineage: flags.suspicious_lineage(),
                score: event.score,
            },
        );

        event
    }
}

impl CompositeBehaviorScorer {
    fn prune_recent_observations(&self, now: DateTime<Utc>) {
        let mut recent_observations = self.recent_observations.borrow_mut();
        while recent_observations.front().is_some_and(|entry| {
            now.signed_duration_since(entry.timestamp).num_seconds()
                > self.recurrence_window_secs as i64
        }) {
            recent_observations.pop_front();
        }
    }

    fn recurrence_component(
        &self,
        batch: &FileActivityBatch,
        process: Option<&ProcessInfo>,
        dominant_extension: Option<&str>,
        weak_identity: bool,
        user_data_targeting: bool,
        suspicious_lineage: bool,
    ) -> Option<(u32, String)> {
        if !user_data_targeting {
            return None;
        }

        let recent_observations = self.recent_observations.borrow();
        let watched_root = normalize_history_value(&batch.watched_root);
        let process_identity = process_history_identity(process);
        let matching_history = recent_observations
            .iter()
            .filter(|entry| {
                if entry.watched_root != watched_root {
                    return false;
                }
                if !entry.user_data_targeting {
                    return false;
                }

                let process_match = process_identity
                    .as_ref()
                    .zip(entry.process_identity.as_ref())
                    .is_some_and(|(current, previous)| current == previous);
                let extension_match = dominant_extension
                    .zip(entry.dominant_extension.as_deref())
                    .is_some_and(|(current, previous)| current == previous);
                let suspicious_context_match = weak_identity
                    && entry.weak_identity
                    && suspicious_lineage
                    && entry.suspicious_lineage;

                process_match || extension_match || suspicious_context_match
            })
            .count()
            .min(u32::MAX as usize) as u32;
        let total_occurrences = matching_history.saturating_add(1);
        if total_occurrences < self.recurrence_min_events {
            return None;
        }

        Some((
            matching_history
                .max(1)
                .saturating_mul(self.recurrence_score),
            format!("recent recurrent activity x{}", total_occurrences),
        ))
    }

    fn remember_observation(
        &self,
        batch: &FileActivityBatch,
        process: Option<&ProcessInfo>,
        context: ObservationContext,
    ) {
        if context.score == 0 {
            return;
        }

        self.recent_observations
            .borrow_mut()
            .push_back(RecentBehaviorObservation {
                timestamp: batch.timestamp,
                watched_root: normalize_history_value(&batch.watched_root),
                process_identity: process_history_identity(process),
                dominant_extension: context.dominant_extension,
                weak_identity: context.weak_identity,
                user_data_targeting: context.user_data_targeting,
                suspicious_lineage: context.suspicious_lineage,
            });
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

fn build_context_flags(batch: &FileActivityBatch, process: Option<&ProcessInfo>) -> ContextFlags {
    let Some(process) = process else {
        return ContextFlags::default();
    };

    ContextFlags {
        known_java_temp_extraction: is_known_java_temp_extraction(process, batch),
        package_manager_helper_activity: is_package_manager_helper_activity(process, batch),
        trusted_maintenance_activity: is_trusted_maintenance_activity(process, batch),
        containerized_service_temp_activity: is_containerized_service_temp_activity(process, batch),
        agent_internal_activity: is_agent_internal_activity(process, batch),
        process_name_mismatch: has_process_name_mismatch(process),
        shell_like_parent: has_shell_like_parent(process),
        temp_path_executable: is_temp_path(&process.exe_path),
    }
}

fn batch_targets_user_data(batch: &FileActivityBatch) -> bool {
    let mut saw_path = false;

    for path in batch
        .touched_paths
        .iter()
        .chain(batch.protected_paths_touched.iter())
    {
        saw_path = true;
        if is_temp_path(path)
            || path_matches_any_prefix(path, MAINTENANCE_PATH_PREFIXES)
            || path_matches_any_prefix(path, AGENT_INTERNAL_PATH_PREFIXES)
        {
            continue;
        }

        if path_matches_any_prefix(path, USER_DATA_PATH_PREFIXES) {
            return true;
        }
    }

    !saw_path && path_matches_any_prefix(&batch.watched_root, USER_DATA_PATH_PREFIXES)
}

fn distinct_parent_dir_count(batch: &FileActivityBatch) -> u32 {
    let directories = batch
        .touched_paths
        .iter()
        .chain(batch.protected_paths_touched.iter())
        .map(|path| {
            Path::new(path)
                .parent()
                .unwrap_or_else(|| Path::new(path))
                .display()
                .to_string()
        })
        .collect::<HashSet<_>>();

    if directories.is_empty() {
        0
    } else {
        directories.len().min(u32::MAX as usize) as u32
    }
}

fn dominant_rename_extension(batch: &FileActivityBatch) -> Option<(String, u32)> {
    let mut counts = std::collections::HashMap::<String, u32>::new();

    for extension in &batch.rename_extension_targets {
        let normalized = extension.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        *counts.entry(normalized).or_insert(0) += 1;
    }

    counts
        .into_iter()
        .max_by(|left, right| left.1.cmp(&right.1).then_with(|| right.0.cmp(&left.0)))
}

fn normalize_history_value(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn process_history_identity(process: Option<&ProcessInfo>) -> Option<String> {
    let process = process?;
    let identity = process.exe_path.trim().to_ascii_lowercase();
    if identity.is_empty() {
        return None;
    }

    let service_unit = process
        .service_unit
        .as_deref()
        .map(normalize_history_value)
        .unwrap_or_else(|| "-".to_string());
    let container = process
        .container_image
        .as_deref()
        .or(process.container_id.as_deref())
        .map(normalize_history_value)
        .unwrap_or_else(|| "-".to_string());
    Some(format!("{identity}|{service_unit}|{container}"))
}

fn adjust_threshold_for_profile(
    base: u32,
    profile: crate::config::ContainmentEnvironmentProfile,
    delta: u32,
) -> u32 {
    match profile {
        crate::config::ContainmentEnvironmentProfile::Conservative => base.saturating_add(delta),
        crate::config::ContainmentEnvironmentProfile::Balanced => base,
        crate::config::ContainmentEnvironmentProfile::Aggressive => base.saturating_sub(delta),
    }
}

fn adjust_signal_requirement_for_profile(
    base: u32,
    profile: crate::config::ContainmentEnvironmentProfile,
) -> u32 {
    match profile {
        crate::config::ContainmentEnvironmentProfile::Conservative => base.saturating_add(1),
        crate::config::ContainmentEnvironmentProfile::Balanced => base,
        crate::config::ContainmentEnvironmentProfile::Aggressive => base.saturating_sub(1).max(1),
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

fn is_recent_process(process: &ProcessInfo, now: DateTime<Utc>, window_secs: u64) -> bool {
    let window_secs = window_secs.max(1);
    let age = now
        .signed_duration_since(process.first_seen_at)
        .num_seconds();
    age >= 0 && age <= i64::try_from(window_secs).unwrap_or(i64::MAX)
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
