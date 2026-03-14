pub mod events;
pub mod lifecycle;

use crate::config::ContainmentConfig;
use crate::correlator::ProcessCorrelator;
use crate::ebpf::events::{
    BehaviorEvent, FileActivityBatch, FileOperationCounts, RawBehaviorEventKind,
    RawBehaviorRingEvent, RAW_BEHAVIOR_PATH_CAPACITY,
};
use crate::ebpf::lifecycle::{LifecycleEvent, ProcessLifecycleTracker};
use crate::scorer::{CompositeBehaviorScorer, Scorer};
use anyhow::{anyhow, Context, Result};
use aya::{
    maps::{Array, MapData, RingBuf},
    programs::TracePoint,
    Ebpf, EbpfLoader,
};
use aya_log::EbpfLogger;
use chrono::Utc;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

const USERSPACE_SENSOR_SOURCE: &str = "userspace_polling";
const AYA_SENSOR_SOURCE: &str = "aya_ringbuf";
const AYA_WATCH_ROOTS_MAP: &str = "BK_WATCH_ROOTS";
const AYA_PROTECTED_ROOTS_MAP: &str = "BK_PROTECTED_ROOTS";
const AYA_DEFAULT_OBJECT_CANDIDATES: &[&str] = &["agent/ebpf/bannkenn-containment.bpf.o"];
const AYA_PATH_PREFIX_CAPACITY: u32 = 16;
const AYA_TRACE_ATTACHMENTS: &[(&str, &str, &str)] = &[
    ("bk_sched_exec", "sched", "sched_process_exec"),
    ("bk_sched_exit", "sched", "sched_process_exit"),
    ("bk_file_openat", "syscalls", "sys_enter_openat"),
    ("bk_file_openat_ret", "syscalls", "sys_exit_openat"),
    ("bk_file_write", "syscalls", "sys_enter_write"),
    ("bk_file_close", "syscalls", "sys_enter_close"),
    ("bk_file_renameat", "syscalls", "sys_enter_renameat"),
    ("bk_file_renameat2", "syscalls", "sys_enter_renameat2"),
    ("bk_file_unlinkat", "syscalls", "sys_enter_unlinkat"),
];
type BackendPollFuture<'a> = Pin<Box<dyn Future<Output = Result<BackendPollResult>> + Send + 'a>>;

trait BehaviorSensorBackend: Send + std::fmt::Debug {
    fn backend_name(&self) -> &'static str;
    fn poll_batches<'a>(&'a mut self, protected_paths: &'a [PathBuf]) -> BackendPollFuture<'a>;
}

#[derive(Debug, Default)]
struct BackendPollResult {
    batches: Vec<FileActivityBatch>,
    lifecycle_events: Vec<LifecycleEvent>,
}

#[derive(Debug)]
pub struct SensorManager {
    poll_interval: Duration,
    protected_paths: Vec<PathBuf>,
    backend: Box<dyn BehaviorSensorBackend>,
    lifecycle: ProcessLifecycleTracker,
    correlator: ProcessCorrelator,
    scorer: CompositeBehaviorScorer,
}

#[derive(Debug)]
struct UserspacePollingBackend {
    poll_interval_ms: u64,
    roots: Vec<PollingRootState>,
}

struct AyaSensorBackend {
    poll_interval_ms: u64,
    watch_roots: Vec<PathBuf>,
    ebpf: Ebpf,
    ring_buf: RingBuf<MapData>,
    logger: Option<EbpfLogger>,
}

impl std::fmt::Debug for AyaSensorBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AyaSensorBackend")
            .field("poll_interval_ms", &self.poll_interval_ms)
            .field("watch_roots", &self.watch_roots)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct PollingRootState {
    root: PathBuf,
    previous: Option<HashMap<FileIdentity, FileSnapshot>>,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawPathPrefixEntry {
    len: u32,
    path: [u8; RAW_BEHAVIOR_PATH_CAPACITY],
}

unsafe impl aya::Pod for RawPathPrefixEntry {}

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

impl Default for RawPathPrefixEntry {
    fn default() -> Self {
        Self {
            len: 0,
            path: [0; RAW_BEHAVIOR_PATH_CAPACITY],
        }
    }
}

impl RawPathPrefixEntry {
    fn from_path(path: &Path) -> Self {
        let mut entry = Self::default();
        let rendered = path.display().to_string();
        let bytes = rendered.as_bytes();
        let len = bytes
            .len()
            .min(RAW_BEHAVIOR_PATH_CAPACITY.saturating_sub(1));
        entry.len = u32::try_from(len).unwrap_or(0);
        entry.path[..len].copy_from_slice(&bytes[..len]);
        entry
    }
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
            protected_paths: config
                .protected_paths
                .iter()
                .filter_map(|path| normalize_path(path))
                .collect(),
            backend: build_backend(config, roots),
            lifecycle: ProcessLifecycleTracker::new(config),
            correlator: ProcessCorrelator::new(),
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
        let mut lifecycle = self.lifecycle.refresh().await?;
        let polled = self.backend.poll_batches(&self.protected_paths).await?;
        merge_lifecycle_events(&mut lifecycle.events, polled.lifecycle_events);

        if !lifecycle.events.is_empty() {
            tracing::debug!(
                "Behavior lifecycle refresh: backend={} active_processes={} transitions={}",
                self.backend.backend_name(),
                lifecycle.processes.len(),
                lifecycle.events.len()
            );
        }

        let mut events = Vec::new();
        for batch in polled.batches {
            let correlation = self.correlator.correlate(&batch, &lifecycle);
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

impl BehaviorSensorBackend for UserspacePollingBackend {
    fn backend_name(&self) -> &'static str {
        USERSPACE_SENSOR_SOURCE
    }

    fn poll_batches<'a>(&'a mut self, protected_paths: &'a [PathBuf]) -> BackendPollFuture<'a> {
        Box::pin(async move {
            let mut result = BackendPollResult::default();

            for root_state in &mut self.roots {
                let root = root_state.root.clone();
                let snapshot = tokio::task::spawn_blocking(move || snapshot_root(&root))
                    .await
                    .context("snapshot task join failed")??;

                let Some(previous) = root_state.previous.replace(snapshot.clone()) else {
                    continue;
                };

                let Some(batch) = build_activity_batch(
                    USERSPACE_SENSOR_SOURCE,
                    &root_state.root,
                    &previous,
                    &snapshot,
                    protected_paths,
                    self.poll_interval_ms,
                ) else {
                    continue;
                };

                result.batches.push(batch);
            }

            Ok(result)
        })
    }
}

impl AyaSensorBackend {
    fn from_config(
        config: &ContainmentConfig,
        watch_roots: Vec<PathBuf>,
        object_path: &Path,
    ) -> Result<Self> {
        let mut ebpf = EbpfLoader::new()
            .load_file(object_path)
            .with_context(|| format!("failed to load eBPF object {}", object_path.display()))?;
        populate_path_prefix_map(&mut ebpf, AYA_WATCH_ROOTS_MAP, &watch_roots)?;
        let protected_paths = config
            .protected_paths
            .iter()
            .filter_map(|path| normalize_path(path))
            .collect::<Vec<_>>();
        populate_path_prefix_map(&mut ebpf, AYA_PROTECTED_ROOTS_MAP, &protected_paths)?;
        let logger = EbpfLogger::init(&mut ebpf).ok();
        attach_default_tracepoints(&mut ebpf)?;
        let ring_buf = RingBuf::try_from(
            ebpf.take_map(&config.ebpf_ringbuf_map)
                .ok_or_else(|| anyhow!("missing ring buffer map {}", config.ebpf_ringbuf_map))?,
        )
        .with_context(|| format!("failed to open ring buffer {}", config.ebpf_ringbuf_map))?;

        Ok(Self {
            poll_interval_ms: config.poll_interval_ms.max(100),
            watch_roots,
            ebpf,
            ring_buf,
            logger,
        })
    }
}

impl BehaviorSensorBackend for AyaSensorBackend {
    fn backend_name(&self) -> &'static str {
        AYA_SENSOR_SOURCE
    }

    fn poll_batches<'a>(&'a mut self, _protected_paths: &'a [PathBuf]) -> BackendPollFuture<'a> {
        Box::pin(async move {
            let _ = self.ebpf.maps().count();
            let _ = self.logger.as_ref();
            let mut result = BackendPollResult::default();
            while let Some(item) = self.ring_buf.next() {
                if let Some(raw) = RawBehaviorRingEvent::from_bytes(&item) {
                    if let Some(lifecycle_event) = raw_ring_event_to_lifecycle_event(raw) {
                        result.lifecycle_events.push(lifecycle_event);
                        continue;
                    }
                    if let Some(batch) =
                        raw_ring_event_to_batch(raw, &self.watch_roots, self.poll_interval_ms)
                    {
                        result.batches.push(batch);
                    }
                }
            }
            Ok(result)
        })
    }
}

fn build_backend(
    config: &ContainmentConfig,
    roots: Vec<PathBuf>,
) -> Box<dyn BehaviorSensorBackend> {
    if let Some(object_path) = resolve_ebpf_object_path(config) {
        match AyaSensorBackend::from_config(config, roots.clone(), &object_path) {
            Ok(backend) => return Box::new(backend),
            Err(error) => tracing::warn!(
                "Failed to initialize Aya backend from {} ({}); falling back to userspace polling",
                object_path.display(),
                error
            ),
        }
    }

    Box::new(UserspacePollingBackend {
        poll_interval_ms: config.poll_interval_ms.max(100),
        roots: roots
            .into_iter()
            .map(|root| PollingRootState {
                root,
                previous: None,
            })
            .collect(),
    })
}

fn attach_default_tracepoints(ebpf: &mut Ebpf) -> Result<()> {
    for (program_name, category, name) in AYA_TRACE_ATTACHMENTS {
        let program = ebpf
            .program_mut(program_name)
            .ok_or_else(|| anyhow!("missing eBPF program {}", program_name))?;
        let program: &mut TracePoint = program
            .try_into()
            .with_context(|| format!("{} is not a tracepoint program", program_name))?;
        program
            .load()
            .with_context(|| format!("failed to load {}", program_name))?;
        program.attach(category, name).with_context(|| {
            format!("failed to attach {} to {}:{}", program_name, category, name)
        })?;
    }
    Ok(())
}

fn resolve_ebpf_object_path(config: &ContainmentConfig) -> Option<PathBuf> {
    if let Some(path) = config.ebpf_object_path.as_deref() {
        return Some(PathBuf::from(path));
    }

    AYA_DEFAULT_OBJECT_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|candidate| candidate.exists())
}

fn populate_path_prefix_map(ebpf: &mut Ebpf, map_name: &str, paths: &[PathBuf]) -> Result<()> {
    let map = ebpf
        .map_mut(map_name)
        .ok_or_else(|| anyhow!("missing eBPF map {}", map_name))?;
    let mut prefixes = Array::<_, RawPathPrefixEntry>::try_from(map)
        .with_context(|| format!("{} is not an array map", map_name))?;

    if paths.len() > AYA_PATH_PREFIX_CAPACITY as usize {
        tracing::warn!(
            "Truncating {} configured paths for {} to {} entries",
            paths.len(),
            map_name,
            AYA_PATH_PREFIX_CAPACITY
        );
    }

    for (index, path) in paths
        .iter()
        .take(AYA_PATH_PREFIX_CAPACITY as usize)
        .enumerate()
    {
        prefixes
            .set(index as u32, RawPathPrefixEntry::from_path(path), 0)
            .with_context(|| format!("failed to populate {}[{}]", map_name, index))?;
    }

    Ok(())
}

fn merge_lifecycle_events(
    existing: &mut Vec<LifecycleEvent>,
    incoming: impl IntoIterator<Item = LifecycleEvent>,
) {
    for event in incoming {
        let duplicate = existing.iter().any(|current| match (&event, current) {
            (LifecycleEvent::Exec { pid: left, .. }, LifecycleEvent::Exec { pid: right, .. }) => {
                left == right
            }
            (LifecycleEvent::Exit { pid: left, .. }, LifecycleEvent::Exit { pid: right, .. }) => {
                left == right
            }
            _ => false,
        });
        if !duplicate {
            existing.push(event);
        }
    }
}

fn raw_ring_event_to_lifecycle_event(raw: RawBehaviorRingEvent) -> Option<LifecycleEvent> {
    let process_name = raw.process_name_string();
    match raw.event_kind() {
        RawBehaviorEventKind::ProcessExec => Some(LifecycleEvent::Exec {
            pid: raw.pid,
            process_name: process_name.clone(),
            exe_path: process_name,
        }),
        RawBehaviorEventKind::ProcessExit => Some(LifecycleEvent::Exit {
            pid: raw.pid,
            process_name,
        }),
        RawBehaviorEventKind::FileActivity | RawBehaviorEventKind::Unknown(_) => None,
    }
}

fn raw_ring_event_to_batch(
    raw: RawBehaviorRingEvent,
    watch_roots: &[PathBuf],
    poll_interval_ms: u64,
) -> Option<FileActivityBatch> {
    if raw.is_lifecycle_event() {
        return None;
    }

    let file_ops = raw.file_ops();
    if file_ops.is_empty() {
        return None;
    }

    let path = raw.path_string();
    let path_buf = (!path.is_empty()).then(|| PathBuf::from(&path));
    let watched_root = path_buf
        .as_ref()
        .and_then(|value| {
            watch_roots
                .iter()
                .find(|root| value.starts_with(root))
                .map(|root| root.display().to_string())
        })
        .or_else(|| watch_roots.first().map(|root| root.display().to_string()))
        .unwrap_or_else(|| "/".to_string());
    let protected_paths_touched = if raw.protected_path_touched != 0 && !path.is_empty() {
        vec![path.clone()]
    } else {
        Vec::new()
    };
    let touched_paths = if path.is_empty() {
        Vec::new()
    } else {
        vec![path]
    };

    Some(FileActivityBatch {
        timestamp: Utc::now(),
        source: AYA_SENSOR_SOURCE.to_string(),
        watched_root,
        poll_interval_ms,
        file_ops,
        touched_paths,
        protected_paths_touched,
        bytes_written: raw.bytes_written,
        io_rate_bytes_per_sec: if poll_interval_ms == 0 {
            raw.bytes_written
        } else {
            raw.bytes_written.saturating_mul(1000) / poll_interval_ms
        },
    })
}

fn build_activity_batch(
    source: &str,
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
        source: source.to_string(),
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
    use crate::ebpf::events::{
        BehaviorLevel, RAW_BEHAVIOR_EVENT_KIND_FILE_ACTIVITY, RAW_BEHAVIOR_EVENT_KIND_PROCESS_EXEC,
    };

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

    #[test]
    fn lifecycle_ring_events_are_translated_without_duplicate_pid_entries() {
        let mut events = vec![LifecycleEvent::Exec {
            pid: 44,
            process_name: "python3".to_string(),
            exe_path: "/usr/bin/python3".to_string(),
        }];
        let raw = RawBehaviorRingEvent {
            pid: 44,
            event_kind: RAW_BEHAVIOR_EVENT_KIND_PROCESS_EXEC,
            bytes_written: 0,
            created: 0,
            modified: 0,
            renamed: 0,
            deleted: 0,
            protected_path_touched: 0,
            path_len: 0,
            process_name_len: 7,
            path: [0; RAW_BEHAVIOR_PATH_CAPACITY],
            process_name: [0; crate::ebpf::events::RAW_BEHAVIOR_PROCESS_CAPACITY],
        };
        let mut raw = raw;
        raw.process_name[..7].copy_from_slice(b"python3");

        merge_lifecycle_events(
            &mut events,
            raw_ring_event_to_lifecycle_event(raw).into_iter(),
        );
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn file_activity_ring_events_ignore_lifecycle_translation() {
        let raw = RawBehaviorRingEvent {
            pid: 7,
            event_kind: RAW_BEHAVIOR_EVENT_KIND_FILE_ACTIVITY,
            bytes_written: 2048,
            created: 0,
            modified: 1,
            renamed: 0,
            deleted: 0,
            protected_path_touched: 1,
            path_len: 13,
            process_name_len: 7,
            path: [0; RAW_BEHAVIOR_PATH_CAPACITY],
            process_name: [0; crate::ebpf::events::RAW_BEHAVIOR_PROCESS_CAPACITY],
        };
        let mut raw = raw;
        raw.path[..13].copy_from_slice(b"/srv/data.txt");
        raw.process_name[..7].copy_from_slice(b"python3");

        assert!(raw_ring_event_to_lifecycle_event(raw).is_none());
        let batch = raw_ring_event_to_batch(raw, &[PathBuf::from("/srv")], 1000).expect("batch");
        assert_eq!(batch.bytes_written, 2048);
        assert_eq!(
            batch.protected_paths_touched,
            vec!["/srv/data.txt".to_string()]
        );
    }
}
