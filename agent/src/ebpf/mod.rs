pub mod events;

use crate::config::ContainmentConfig;
use crate::correlator::ProcessCorrelator;
use crate::ebpf::events::{BehaviorEvent, FileActivityBatch, FileOperationCounts};
use crate::scorer::{CompositeBehaviorScorer, Scorer};
use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

const SENSOR_SOURCE: &str = "userspace_polling";

#[derive(Debug)]
pub struct SensorManager {
    poll_interval: Duration,
    poll_interval_ms: u64,
    protected_paths: Vec<PathBuf>,
    roots: Vec<PollingRootState>,
    correlator: ProcessCorrelator,
    scorer: CompositeBehaviorScorer,
}

#[derive(Debug)]
struct PollingRootState {
    root: PathBuf,
    previous: Option<HashMap<FileIdentity, FileSnapshot>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FileIdentity {
    dev: u64,
    ino: u64,
}

#[derive(Debug, Clone)]
struct FileSnapshot {
    path: PathBuf,
    len: u64,
    modified_ns: i128,
}

impl SensorManager {
    pub fn from_config(config: &ContainmentConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }

        let roots = config
            .watch_paths
            .iter()
            .filter_map(|path| normalize_path(path))
            .collect::<Vec<_>>();
        if roots.is_empty() {
            return None;
        }

        Some(Self {
            poll_interval: Duration::from_millis(config.poll_interval_ms.max(100)),
            poll_interval_ms: config.poll_interval_ms.max(100),
            protected_paths: config
                .protected_paths
                .iter()
                .filter_map(|path| normalize_path(path))
                .collect(),
            roots: roots
                .into_iter()
                .map(|root| PollingRootState {
                    root,
                    previous: None,
                })
                .collect(),
            correlator: ProcessCorrelator::new(config),
            scorer: CompositeBehaviorScorer::from_config(config),
        })
    }

    pub async fn run(mut self, tx: mpsc::Sender<BehaviorEvent>) -> Result<()> {
        let mut ticker = interval(self.poll_interval);
        ticker.tick().await;

        loop {
            ticker.tick().await;
            for event in self.poll_once().await? {
                if tx.send(event).await.is_err() {
                    return Ok(());
                }
            }
        }
    }

    pub async fn poll_once(&mut self) -> Result<Vec<BehaviorEvent>> {
        let mut events = Vec::new();

        for root_state in &mut self.roots {
            let root = root_state.root.clone();
            let snapshot = tokio::task::spawn_blocking(move || snapshot_root(&root))
                .await
                .context("snapshot task join failed")??;

            let Some(previous) = root_state.previous.replace(snapshot.clone()) else {
                continue;
            };

            let Some(batch) = build_activity_batch(
                &root_state.root,
                &previous,
                &snapshot,
                &self.protected_paths,
                self.poll_interval_ms,
            ) else {
                continue;
            };

            let correlation = self.correlator.correlate(&batch);
            if correlation.process.is_none() && correlation.protected_hits > 0 {
                continue;
            }

            let event = self.scorer.score(&batch, &correlation);
            if !event.file_ops.is_empty() {
                events.push(event);
            }
        }

        Ok(events)
    }
}

fn build_activity_batch(
    root: &Path,
    previous: &HashMap<FileIdentity, FileSnapshot>,
    current: &HashMap<FileIdentity, FileSnapshot>,
    protected_paths: &[PathBuf],
    poll_interval_ms: u64,
) -> Option<FileActivityBatch> {
    let mut file_ops = FileOperationCounts::default();
    let mut touched_paths = BTreeSet::new();
    let mut protected_touched = BTreeSet::new();
    let mut bytes_written = 0u64;

    for (identity, now) in current {
        match previous.get(identity) {
            Some(before) => {
                if before.path != now.path {
                    file_ops.renamed = file_ops.renamed.saturating_add(1);
                    insert_touched_path(
                        before.path.as_path(),
                        protected_paths,
                        &mut touched_paths,
                        &mut protected_touched,
                    );
                    insert_touched_path(
                        now.path.as_path(),
                        protected_paths,
                        &mut touched_paths,
                        &mut protected_touched,
                    );
                }

                if before.modified_ns != now.modified_ns || before.len != now.len {
                    file_ops.modified = file_ops.modified.saturating_add(1);
                    bytes_written =
                        bytes_written.saturating_add(now.len.saturating_sub(before.len));
                    insert_touched_path(
                        now.path.as_path(),
                        protected_paths,
                        &mut touched_paths,
                        &mut protected_touched,
                    );
                }
            }
            None => {
                file_ops.created = file_ops.created.saturating_add(1);
                insert_touched_path(
                    now.path.as_path(),
                    protected_paths,
                    &mut touched_paths,
                    &mut protected_touched,
                );
            }
        }
    }

    for (identity, before) in previous {
        if !current.contains_key(identity) {
            file_ops.deleted = file_ops.deleted.saturating_add(1);
            insert_touched_path(
                before.path.as_path(),
                protected_paths,
                &mut touched_paths,
                &mut protected_touched,
            );
        }
    }

    if file_ops.is_empty() {
        return None;
    }

    let io_rate_bytes_per_sec = if poll_interval_ms == 0 {
        bytes_written
    } else {
        bytes_written.saturating_mul(1000) / poll_interval_ms
    };

    Some(FileActivityBatch {
        timestamp: Utc::now(),
        source: SENSOR_SOURCE.to_string(),
        watched_root: root.display().to_string(),
        poll_interval_ms,
        file_ops,
        touched_paths: touched_paths.into_iter().collect(),
        protected_paths_touched: protected_touched.into_iter().collect(),
        bytes_written,
        io_rate_bytes_per_sec,
    })
}

fn insert_touched_path(
    path: &Path,
    protected_paths: &[PathBuf],
    touched_paths: &mut BTreeSet<String>,
    protected_touched: &mut BTreeSet<String>,
) {
    let display = path.display().to_string();
    touched_paths.insert(display.clone());
    if protected_paths
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        protected_touched.insert(display);
    }
}

fn normalize_path(path: &str) -> Option<PathBuf> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }

    let candidate = PathBuf::from(trimmed);
    Some(fs::canonicalize(&candidate).unwrap_or(candidate))
}

fn snapshot_root(root: &Path) -> Result<HashMap<FileIdentity, FileSnapshot>> {
    let mut snapshots = HashMap::new();
    if !root.exists() {
        return Ok(snapshots);
    }

    collect_snapshots(root, &mut snapshots)?;
    Ok(snapshots)
}

fn collect_snapshots(root: &Path, out: &mut HashMap<FileIdentity, FileSnapshot>) -> Result<()> {
    let metadata =
        fs::symlink_metadata(root).with_context(|| format!("failed to stat {}", root.display()))?;

    if metadata.file_type().is_symlink() {
        return Ok(());
    }

    if metadata.is_file() {
        record_snapshot(root, &metadata, out);
        return Ok(());
    }

    if !metadata.is_dir() {
        return Ok(());
    }

    let entries =
        fs::read_dir(root).with_context(|| format!("failed to read {}", root.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };

        if metadata.file_type().is_symlink() {
            continue;
        }

        if metadata.is_dir() {
            collect_snapshots(&path, out)?;
        } else if metadata.is_file() {
            record_snapshot(&path, &metadata, out);
        }
    }

    Ok(())
}

#[cfg(unix)]
fn record_snapshot(
    path: &Path,
    metadata: &fs::Metadata,
    out: &mut HashMap<FileIdentity, FileSnapshot>,
) {
    let identity = FileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    };
    let modified_ns = i128::from(metadata.mtime())
        .saturating_mul(1_000_000_000)
        .saturating_add(i128::from(metadata.mtime_nsec()));
    out.insert(
        identity,
        FileSnapshot {
            path: path.to_path_buf(),
            len: metadata.len(),
            modified_ns,
        },
    );
}

#[cfg(not(unix))]
fn record_snapshot(
    path: &Path,
    metadata: &fs::Metadata,
    out: &mut HashMap<FileIdentity, FileSnapshot>,
) {
    let _ = (path, metadata, out);
    unreachable!("Phase 1 filesystem containment is Linux-only")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ContainmentConfig;
    use crate::ebpf::events::BehaviorLevel;

    #[tokio::test]
    async fn simulated_mass_rename_triggers_score_above_suspicious_threshold() {
        let root = std::env::temp_dir().join(format!("bannkenn-phase1-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();

        let mut open_files = Vec::new();
        for idx in 0..8 {
            let path = root.join(format!("file-{}.txt", idx));
            fs::write(&path, format!("payload-{}", idx)).unwrap();
        }

        let mut config = ContainmentConfig {
            enabled: true,
            watch_paths: vec![root.display().to_string()],
            ..ContainmentConfig::default()
        };
        config
            .protected_pid_allowlist
            .retain(|entry| entry != "bannkenn-agent");
        let mut sensor = SensorManager::from_config(&config).expect("sensor should be enabled");
        assert!(
            sensor.poll_once().await.unwrap().is_empty(),
            "baseline poll"
        );

        for idx in 0..8 {
            let from = root.join(format!("file-{}.txt", idx));
            open_files.push(fs::File::open(&from).unwrap());
            let to = root.join(format!("file-{}.locked", idx));
            fs::rename(&from, &to).unwrap();
        }

        let events = sensor.poll_once().await.unwrap();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert!(event.file_ops.renamed >= 8);
        assert!(event.score > 30);
        assert_eq!(event.level, BehaviorLevel::Suspicious);
        assert_eq!(event.pid, Some(std::process::id()));

        drop(open_files);
        let _ = fs::remove_dir_all(root);
    }
}
