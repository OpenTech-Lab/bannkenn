pub mod events;
pub mod lifecycle;

use crate::config::ContainmentConfig;
use crate::correlator::ProcessCorrelator;
use crate::ebpf::events::{
    BehaviorEvent, FileActivityBatch, FileOperationCounts, RAW_BEHAVIOR_PATH_CAPACITY,
};
#[cfg(any(target_os = "linux", test))]
use crate::ebpf::events::{RawBehaviorEventKind, RawBehaviorRingEvent};
use crate::ebpf::lifecycle::{LifecycleEvent, ProcessLifecycleTracker};
use crate::scorer::CompositeBehaviorScorer;
use crate::shared_risk::SharedRiskSnapshot;
#[cfg(target_os = "linux")]
use anyhow::anyhow;
use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use aya::{
    maps::{Array, MapData, RingBuf},
    programs::TracePoint,
    Ebpf, EbpfLoader, VerifierLogLevel,
};
#[cfg(target_os = "linux")]
use aya_log::EbpfLogger;
use chrono::Utc;
use std::collections::{hash_map::Entry, BTreeSet, HashMap};
use std::fs;
use std::future::Future;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, Duration};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

const USERSPACE_SENSOR_SOURCE: &str = "userspace_polling";
const LIFECYCLE_EXEC_SENSOR_SOURCE: &str = "lifecycle_exec";
#[cfg(target_os = "linux")]
const AYA_SENSOR_SOURCE: &str = "aya_ringbuf";
#[cfg(target_os = "linux")]
const AYA_WATCH_ROOTS_MAP: &str = "BK_WATCH_ROOTS";
#[cfg(target_os = "linux")]
const AYA_PROTECTED_ROOTS_MAP: &str = "BK_PROTECTED_ROOTS";
#[cfg(target_os = "linux")]
const AYA_DEFAULT_OBJECT_CANDIDATES: &[&str] = &[
    "agent/ebpf/bannkenn-containment.bpf.o",
    "/usr/lib/bannkenn/ebpf/bannkenn-containment.bpf.o",
    "/usr/local/lib/bannkenn/ebpf/bannkenn-containment.bpf.o",
];
#[cfg(target_os = "linux")]
const AYA_PATH_PREFIX_CAPACITY: u32 = 16;
#[cfg(target_os = "linux")]
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
const RECENT_TEMP_WRITE_WINDOW_SECS: u64 = 60;
const USERSPACE_MAX_IDLE_SKIP_POLLS: u32 = 15;
const AYA_MAX_RING_EVENTS_PER_POLL: usize = 512;
const AYA_BACKPRESSURE_WARNING_COOLDOWN_SECS: u64 = 30;
const CONTENT_PROFILE_MIN_SAMPLE_BYTES: usize = 256;
const HIGH_ENTROPY_THRESHOLD_X100: u16 = 720;
const HIGH_ENTROPY_DELTA_X100: u16 = 80;
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
    shared_risk_snapshot: Arc<RwLock<SharedRiskSnapshot>>,
    recent_temp_writes: HashMap<String, RecentTempWrite>,
    content_profile_tracker: Option<ContentProfileTracker>,
}

#[derive(Debug)]
struct UserspacePollingBackend {
    poll_interval_ms: u64,
    roots: Vec<PollingRootState>,
}

#[cfg(target_os = "linux")]
struct AyaSensorBackend {
    poll_interval_ms: u64,
    watch_roots: Vec<PathBuf>,
    ebpf: Ebpf,
    ring_buf: RingBuf<MapData>,
    logger: Option<EbpfLogger>,
    backpressure_warning: RateLimitedWarning,
}

#[cfg(target_os = "linux")]
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
    idle_scan_streak: u32,
    skip_polls_remaining: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawPathPrefixEntry {
    len: u32,
    path: [u8; RAW_BEHAVIOR_PATH_CAPACITY],
}

#[cfg(target_os = "linux")]
unsafe impl aya::Pod for RawPathPrefixEntry {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FileIdentity {
    dev: u64,
    ino: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileSnapshot {
    path: PathBuf,
    len: u64,
    modified_ns: i128,
}

#[derive(Debug, Clone)]
struct RecentTempWrite {
    recorded_at: Instant,
    watched_root: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileContentProfile {
    sample_bytes: u16,
    entropy_x100: u16,
    utf8_valid: bool,
}

#[derive(Debug)]
struct ContentProfileTracker {
    roots: Vec<PathBuf>,
    sample_bytes: usize,
    initialized: bool,
    profiles: HashMap<String, FileContentProfile>,
}

#[derive(Debug, Clone)]
struct RateLimitedWarning {
    cooldown: Duration,
    last_emitted: Option<Instant>,
    suppressed: u32,
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

impl PollingRootState {
    fn should_scan(&mut self) -> bool {
        if self.skip_polls_remaining == 0 {
            return true;
        }

        self.skip_polls_remaining = self.skip_polls_remaining.saturating_sub(1);
        false
    }

    fn record_idle_scan(&mut self) {
        self.idle_scan_streak = self.idle_scan_streak.saturating_add(1);
        self.skip_polls_remaining = idle_skip_polls(self.idle_scan_streak);
    }

    fn record_activity(&mut self) {
        self.idle_scan_streak = 0;
        self.skip_polls_remaining = 0;
    }
}

impl RateLimitedWarning {
    fn new(cooldown: Duration) -> Self {
        Self {
            cooldown,
            last_emitted: None,
            suppressed: 0,
        }
    }

    fn next_message(&mut self, message: impl Into<String>) -> Option<String> {
        let now = Instant::now();
        if let Some(last_emitted) = self.last_emitted {
            if now.duration_since(last_emitted) < self.cooldown {
                self.suppressed = self.suppressed.saturating_add(1);
                return None;
            }
        }

        let message = message.into();
        let rendered = if self.suppressed == 0 {
            message
        } else {
            format!(
                "{} (suppressed {} similar warning(s))",
                message, self.suppressed
            )
        };
        self.last_emitted = Some(now);
        self.suppressed = 0;
        Some(rendered)
    }
}

impl SensorManager {
    #[allow(unreachable_code)]
    pub fn from_config(
        config: &ContainmentConfig,
        shared_risk_snapshot: Arc<RwLock<SharedRiskSnapshot>>,
    ) -> Option<Self> {
        if !config.enabled {
            return None;
        }

        #[cfg(not(target_os = "linux"))]
        {
            tracing::warn!(
                "Containment sensor requested on {}; filesystem containment is Linux-only and will stay disabled",
                std::env::consts::OS
            );
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
        let content_profile_roots = roots.clone();

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
            shared_risk_snapshot,
            recent_temp_writes: HashMap::new(),
            content_profile_tracker: Some(ContentProfileTracker::new(
                content_profile_roots,
                config.content_profile_sample_bytes,
            )),
        })
    }

    pub fn backend_name(&self) -> &'static str {
        self.backend.backend_name()
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
        let mut polled = self.backend.poll_batches(&self.protected_paths).await?;
        polled.batches = coalesce_activity_batches(polled.batches);
        self.annotate_content_indicators(&mut polled.batches)
            .await?;
        merge_lifecycle_events(&mut lifecycle.events, polled.lifecycle_events);
        let now = Instant::now();
        self.prune_recent_temp_writes(now);
        self.record_temp_writes(&polled.batches, now);

        if !lifecycle.events.is_empty() {
            tracing::debug!(
                "Behavior lifecycle refresh: backend={} active_processes={} transitions={}",
                self.backend.backend_name(),
                lifecycle.processes.len(),
                lifecycle.events.len()
            );
        }

        let mut events = self.build_temp_exec_events(&lifecycle);
        let shared_risk_snapshot = self.shared_risk_snapshot.read().await.clone();
        for batch in polled.batches {
            let correlation = self.correlator.correlate(&batch, &lifecycle);
            if correlation.process.is_none() && correlation.protected_hits > 0 {
                continue;
            }

            let event =
                self.scorer
                    .score_with_shared_risk(&batch, &correlation, &shared_risk_snapshot);
            if !event.file_ops.is_empty() {
                events.push(event);
            }
        }

        Ok(events)
    }

    async fn annotate_content_indicators(
        &mut self,
        batches: &mut Vec<FileActivityBatch>,
    ) -> Result<()> {
        let Some(mut tracker) = self.content_profile_tracker.take() else {
            return Ok(());
        };
        let mut local_batches = std::mem::take(batches);
        let (tracker, local_batches) = tokio::task::spawn_blocking(
            move || -> (ContentProfileTracker, Vec<FileActivityBatch>) {
                tracker.ensure_initialized();
                tracker.annotate_batches(&mut local_batches);
                (tracker, local_batches)
            },
        )
        .await
        .context("content profile task join failed")?;
        self.content_profile_tracker = Some(tracker);
        *batches = local_batches;
        Ok(())
    }

    fn prune_recent_temp_writes(&mut self, now: Instant) {
        self.recent_temp_writes.retain(|_, entry| {
            now.duration_since(entry.recorded_at)
                <= Duration::from_secs(RECENT_TEMP_WRITE_WINDOW_SECS)
        });
    }

    fn record_temp_writes(&mut self, batches: &[FileActivityBatch], now: Instant) {
        for batch in batches {
            if batch.file_ops.created == 0 && batch.file_ops.modified == 0 {
                continue;
            }

            for path in batch.touched_paths.iter().filter(|path| is_temp_path(path)) {
                self.recent_temp_writes.insert(
                    path.clone(),
                    RecentTempWrite {
                        recorded_at: now,
                        watched_root: batch.watched_root.clone(),
                    },
                );
            }
        }
    }

    fn build_temp_exec_events(
        &self,
        lifecycle: &crate::ebpf::lifecycle::LifecycleSnapshot,
    ) -> Vec<BehaviorEvent> {
        lifecycle
            .events
            .iter()
            .filter_map(|event| match event {
                LifecycleEvent::Exec { pid, exe_path, .. } => {
                    let process = lifecycle
                        .processes
                        .iter()
                        .find(|proc_info| proc_info.pid == *pid)
                        .map(process_info_from_tracked);
                    let matched_path = process
                        .as_ref()
                        .map(|proc_info| proc_info.exe_path.as_str())
                        .filter(|path| is_temp_path(path))
                        .unwrap_or(exe_path);
                    if !is_temp_path(matched_path) {
                        return None;
                    }
                    let recent = self.recent_temp_writes.get(matched_path)?;
                    Some(self.scorer.score_temp_exec_trigger(
                        Utc::now(),
                        LIFECYCLE_EXEC_SENSOR_SOURCE,
                        &recent.watched_root,
                        matched_path,
                        process.as_ref(),
                    ))
                }
                LifecycleEvent::Exit { .. } => None,
            })
            .collect()
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
                if !root_state.should_scan() {
                    continue;
                }

                let root = root_state.root.clone();
                let snapshot = tokio::task::spawn_blocking(move || snapshot_root(&root))
                    .await
                    .context("snapshot task join failed")??;

                let Some(previous) = root_state.previous.replace(snapshot) else {
                    continue;
                };
                let changed = root_state
                    .previous
                    .as_ref()
                    .map(|current| &previous != current)
                    .unwrap_or(false);

                if !changed {
                    root_state.record_idle_scan();
                    continue;
                }

                root_state.record_activity();
                let current = root_state
                    .previous
                    .as_ref()
                    .expect("current snapshot should be present");

                let Some(batch) = build_activity_batch(
                    USERSPACE_SENSOR_SOURCE,
                    &root_state.root,
                    &previous,
                    current,
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

#[cfg(target_os = "linux")]
impl AyaSensorBackend {
    fn from_config(
        config: &ContainmentConfig,
        watch_roots: Vec<PathBuf>,
        object_path: &Path,
    ) -> Result<Self> {
        let mut ebpf = EbpfLoader::new()
            .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
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
            backpressure_warning: RateLimitedWarning::new(Duration::from_secs(
                AYA_BACKPRESSURE_WARNING_COOLDOWN_SECS,
            )),
        })
    }
}

#[cfg(target_os = "linux")]
impl BehaviorSensorBackend for AyaSensorBackend {
    fn backend_name(&self) -> &'static str {
        AYA_SENSOR_SOURCE
    }

    fn poll_batches<'a>(&'a mut self, _protected_paths: &'a [PathBuf]) -> BackendPollFuture<'a> {
        Box::pin(async move {
            let _ = self.ebpf.maps().count();
            let _ = self.logger.as_ref();
            let mut result = BackendPollResult::default();
            let mut drained = 0usize;
            while drained < AYA_MAX_RING_EVENTS_PER_POLL {
                let Some(item) = self.ring_buf.next() else {
                    break;
                };
                drained = drained.saturating_add(1);
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
            if drained == AYA_MAX_RING_EVENTS_PER_POLL {
                if let Some(message) = self.backpressure_warning.next_message(format!(
                    "Containment ring buffer drain hit the per-poll cap of {}; continuing on the next tick",
                    AYA_MAX_RING_EVENTS_PER_POLL
                )) {
                    tracing::warn!("{}", message);
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
    #[cfg(target_os = "linux")]
    {
        if let Some(object_path) = resolve_ebpf_object_path(config) {
            match AyaSensorBackend::from_config(config, roots.clone(), &object_path) {
                Ok(backend) => {
                    tracing::info!(
                        "Containment Aya backend initialized from {}",
                        object_path.display()
                    );
                    return Box::new(backend);
                }
                Err(error) => tracing::warn!(
                    "Failed to initialize Aya backend from {} ({:#}); falling back to userspace polling",
                    object_path.display(),
                    error
                ),
            }
        }
    }

    tracing::info!("Containment userspace polling backend active");
    Box::new(UserspacePollingBackend {
        poll_interval_ms: config.poll_interval_ms.max(100),
        roots: roots
            .into_iter()
            .map(|root| PollingRootState {
                root,
                previous: None,
                idle_scan_streak: 0,
                skip_polls_remaining: 0,
            })
            .collect(),
    })
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn resolve_ebpf_object_path(config: &ContainmentConfig) -> Option<PathBuf> {
    if let Some(path) = config.ebpf_object_path.as_deref() {
        return Some(PathBuf::from(path));
    }

    AYA_DEFAULT_OBJECT_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|candidate| candidate.exists())
}

#[cfg(target_os = "linux")]
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

fn idle_skip_polls(idle_scan_streak: u32) -> u32 {
    ((1u32 << idle_scan_streak.min(4)) - 1).min(USERSPACE_MAX_IDLE_SKIP_POLLS)
}

fn coalesce_activity_batches(batches: Vec<FileActivityBatch>) -> Vec<FileActivityBatch> {
    if batches.len() <= 1 {
        return batches;
    }

    let mut merged = HashMap::<(String, String), FileActivityBatch>::new();
    for batch in batches {
        let key = (batch.source.clone(), batch.watched_root.clone());
        match merged.entry(key) {
            Entry::Occupied(mut entry) => merge_activity_batch(entry.get_mut(), batch),
            Entry::Vacant(entry) => {
                entry.insert(batch);
            }
        }
    }

    let mut coalesced = merged.into_values().collect::<Vec<_>>();
    coalesced.sort_by(|left, right| {
        left.watched_root
            .cmp(&right.watched_root)
            .then_with(|| left.source.cmp(&right.source))
    });
    coalesced
}

fn merge_activity_batch(target: &mut FileActivityBatch, mut incoming: FileActivityBatch) {
    target.timestamp = target.timestamp.max(incoming.timestamp);
    target.poll_interval_ms = target.poll_interval_ms.max(incoming.poll_interval_ms);
    target.file_ops.created = target
        .file_ops
        .created
        .saturating_add(incoming.file_ops.created);
    target.file_ops.modified = target
        .file_ops
        .modified
        .saturating_add(incoming.file_ops.modified);
    target.file_ops.renamed = target
        .file_ops
        .renamed
        .saturating_add(incoming.file_ops.renamed);
    target.file_ops.deleted = target
        .file_ops
        .deleted
        .saturating_add(incoming.file_ops.deleted);
    target.bytes_written = target.bytes_written.saturating_add(incoming.bytes_written);
    target.io_rate_bytes_per_sec = target
        .io_rate_bytes_per_sec
        .saturating_add(incoming.io_rate_bytes_per_sec);
    target.touched_paths.append(&mut incoming.touched_paths);
    target.touched_paths.sort();
    target.touched_paths.dedup();
    target
        .protected_paths_touched
        .append(&mut incoming.protected_paths_touched);
    target.protected_paths_touched.sort();
    target.protected_paths_touched.dedup();
    target
        .rename_extension_targets
        .append(&mut incoming.rename_extension_targets);
    target.content_indicators.unreadable_rewrites = target
        .content_indicators
        .unreadable_rewrites
        .saturating_add(incoming.content_indicators.unreadable_rewrites);
    target.content_indicators.high_entropy_rewrites = target
        .content_indicators
        .high_entropy_rewrites
        .saturating_add(incoming.content_indicators.high_entropy_rewrites);
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
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
        rename_extension_targets: Vec::new(),
        content_indicators: Default::default(),
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
    let mut rename_extension_targets = Vec::new();
    let mut bytes_written = 0u64;

    for (identity, now) in current {
        match previous.get(identity) {
            Some(before) => {
                if before.path != now.path {
                    file_ops.renamed = file_ops.renamed.saturating_add(1);
                    if let Some(extension) =
                        renamed_extension_target(before.path.as_path(), now.path.as_path())
                    {
                        rename_extension_targets.push(extension);
                    }
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
        rename_extension_targets,
        content_indicators: Default::default(),
        bytes_written,
        io_rate_bytes_per_sec,
    })
}

fn renamed_extension_target(before: &Path, after: &Path) -> Option<String> {
    let previous = normalized_extension(before)?;
    let current = normalized_extension(after)?;
    (previous != current).then_some(current)
}

fn normalized_extension(path: &Path) -> Option<String> {
    let extension = path.extension()?.to_str()?.trim().to_ascii_lowercase();
    (!extension.is_empty()).then_some(extension)
}

impl ContentProfileTracker {
    fn new(roots: Vec<PathBuf>, sample_bytes: u64) -> Self {
        let sample_bytes = usize::try_from(sample_bytes)
            .ok()
            .filter(|value| *value >= CONTENT_PROFILE_MIN_SAMPLE_BYTES)
            .unwrap_or(CONTENT_PROFILE_MIN_SAMPLE_BYTES);

        Self {
            roots,
            sample_bytes,
            initialized: false,
            profiles: HashMap::new(),
        }
    }

    fn ensure_initialized(&mut self) {
        if self.initialized {
            return;
        }

        let mut profiles = HashMap::new();
        for root in &self.roots {
            collect_content_profiles(root, self.sample_bytes, &mut profiles);
        }
        self.profiles = profiles;
        self.initialized = true;
    }

    fn annotate_batches(&mut self, batches: &mut [FileActivityBatch]) {
        for batch in batches {
            self.annotate_batch(batch);
        }
    }

    fn annotate_batch(&mut self, batch: &mut FileActivityBatch) {
        let mut content_indicators = crate::ebpf::events::FileContentIndicators::default();
        let touched_paths = batch
            .touched_paths
            .iter()
            .chain(batch.protected_paths_touched.iter())
            .cloned()
            .collect::<BTreeSet<_>>();

        for path in touched_paths {
            let previous = self.profiles.get(&path).copied();
            match sample_file_content_profile(Path::new(&path), self.sample_bytes) {
                Some(current) => {
                    if let Some(previous) = previous {
                        if is_unreadable_rewrite(previous, current) {
                            content_indicators.unreadable_rewrites =
                                content_indicators.unreadable_rewrites.saturating_add(1);
                        }
                        if is_high_entropy_rewrite(previous, current) {
                            content_indicators.high_entropy_rewrites =
                                content_indicators.high_entropy_rewrites.saturating_add(1);
                        }
                    }
                    self.profiles.insert(path, current);
                }
                None => {
                    self.profiles.remove(&path);
                }
            }
        }

        batch.content_indicators = content_indicators;
    }
}

fn collect_content_profiles(
    root: &Path,
    sample_bytes: usize,
    out: &mut HashMap<String, FileContentProfile>,
) {
    let Ok(metadata) = fs::symlink_metadata(root) else {
        return;
    };

    if metadata.file_type().is_symlink() {
        return;
    }

    if metadata.is_file() {
        if let Some(profile) = sample_file_content_profile(root, sample_bytes) {
            out.insert(root.display().to_string(), profile);
        }
        return;
    }

    if !metadata.is_dir() {
        return;
    }

    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        collect_content_profiles(&entry.path(), sample_bytes, out);
    }
}

fn sample_file_content_profile(path: &Path, sample_bytes: usize) -> Option<FileContentProfile> {
    let mut file = fs::File::open(path).ok()?;
    let mut sample = vec![0u8; sample_bytes];
    let read = file.read(&mut sample).ok()?;
    if read < CONTENT_PROFILE_MIN_SAMPLE_BYTES {
        return None;
    }
    sample.truncate(read);

    Some(FileContentProfile {
        sample_bytes: read.min(u16::MAX as usize) as u16,
        entropy_x100: shannon_entropy_x100(&sample),
        utf8_valid: std::str::from_utf8(&sample).is_ok(),
    })
}

fn shannon_entropy_x100(sample: &[u8]) -> u16 {
    let mut counts = [0u32; 256];
    for byte in sample {
        counts[*byte as usize] = counts[*byte as usize].saturating_add(1);
    }

    let total = sample.len() as f64;
    let mut entropy = 0.0f64;
    for count in counts.into_iter().filter(|count| *count > 0) {
        let probability = f64::from(count) / total;
        entropy -= probability * probability.log2();
    }

    (entropy * 100.0).round().clamp(0.0, f64::from(u16::MAX)) as u16
}

fn is_unreadable_rewrite(previous: FileContentProfile, current: FileContentProfile) -> bool {
    previous.utf8_valid && !current.utf8_valid
}

fn is_high_entropy_rewrite(previous: FileContentProfile, current: FileContentProfile) -> bool {
    previous.sample_bytes >= CONTENT_PROFILE_MIN_SAMPLE_BYTES as u16
        && current.sample_bytes >= CONTENT_PROFILE_MIN_SAMPLE_BYTES as u16
        && current.entropy_x100 >= HIGH_ENTROPY_THRESHOLD_X100
        && current.entropy_x100
            >= previous
                .entropy_x100
                .saturating_add(HIGH_ENTROPY_DELTA_X100)
}

fn process_info_from_tracked(
    process: &crate::ebpf::lifecycle::TrackedProcess,
) -> crate::ebpf::events::ProcessInfo {
    crate::ebpf::events::ProcessInfo {
        pid: process.pid,
        parent_pid: process.parent_pid,
        uid: process.uid,
        gid: process.gid,
        service_unit: process.service_unit.clone(),
        first_seen_at: process.first_seen_at,
        trust_class: process.trust_class,
        trust_policy_name: process.trust_policy_name.clone(),
        maintenance_activity: process.maintenance_activity,
        trust_policy_visibility: process.trust_policy_visibility,
        package_name: process.package_name.clone(),
        package_manager: process.package_manager.clone(),
        process_name: process.process_name.clone(),
        exe_path: process.exe_path.clone(),
        command_line: process.command_line.clone(),
        correlation_hits: 0,
        parent_process_name: process.parent_process_name.clone(),
        parent_command_line: process.parent_command_line.clone(),
        parent_chain: process.parent_chain.clone(),
        container_runtime: process.container_runtime.clone(),
        container_id: process.container_id.clone(),
        container_image: process.container_image.clone(),
        orchestrator: process.orchestrator.clone(),
        container_mounts: process.container_mounts.clone(),
    }
}

fn is_temp_path(path: &str) -> bool {
    let trimmed = path.trim();
    trimmed == "/tmp"
        || trimmed.starts_with("/tmp/")
        || trimmed == "/var/tmp"
        || trimmed.starts_with("/var/tmp/")
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
#[path = "../../tests/unit/ebpf/mod_tests.rs"]
mod tests;
