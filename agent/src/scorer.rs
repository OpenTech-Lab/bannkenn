use crate::config::ContainmentConfig;
use crate::correlator::CorrelationResult;
use crate::ebpf::events::{BehaviorEvent, BehaviorLevel, FileActivityBatch};

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
}

impl Scorer for CompositeBehaviorScorer {
    fn score(&self, batch: &FileActivityBatch, correlation: &CorrelationResult) -> BehaviorEvent {
        let mut score = 0u32;
        let mut reasons = Vec::new();

        if batch.file_ops.renamed > 0 {
            let rename_score = batch.file_ops.renamed.saturating_mul(self.rename_score);
            score = score.saturating_add(rename_score);
            reasons.push(format!("rename burst x{}", batch.file_ops.renamed));
        }

        if batch.file_ops.modified > 0 {
            let write_score = batch.file_ops.modified.saturating_mul(self.write_score);
            score = score.saturating_add(write_score);
            reasons.push(format!("write burst x{}", batch.file_ops.modified));
        }

        if batch.file_ops.deleted > 0 {
            let delete_score = batch.file_ops.deleted.saturating_mul(self.delete_score);
            score = score.saturating_add(delete_score);
            reasons.push(format!("delete burst x{}", batch.file_ops.deleted));
        }

        if !batch.protected_paths_touched.is_empty() {
            score = score.saturating_add(self.protected_path_bonus);
            reasons.push("protected path touched".to_string());
        }

        if correlation.process.is_none() && !batch.file_ops.is_empty() {
            score = score.saturating_add(self.unknown_process_bonus);
            reasons.push("unknown process activity".to_string());
        }

        let throughput_score =
            (batch.bytes_written / self.bytes_per_score).min(u64::from(u32::MAX)) as u32;
        if throughput_score > 0 {
            score = score.saturating_add(throughput_score);
            reasons.push(format!(
                "write throughput {}B/s",
                batch.io_rate_bytes_per_sec
            ));
        }

        let process = correlation.process.as_ref();
        let level = self.classify_level(score);

        BehaviorEvent {
            timestamp: batch.timestamp.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ContainmentConfig;
    use crate::ebpf::events::{FileActivityBatch, FileOperationCounts, ProcessInfo};
    use chrono::Utc;

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
            }),
            protected_hits: 0,
        };

        let event = scorer.score(&batch, &correlation);
        assert_eq!(event.level, BehaviorLevel::Suspicious);
        assert!(event.score > 30);
    }
}
