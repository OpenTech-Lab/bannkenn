## Investigation — 2026-03-15
- [x] Review existing project lessons for relevant workflow constraints
- [x] Trace whether `z_wr_iss` exists literally or as a derived identifier in agent/server code
- [x] Confirm whether any server runtime path invokes, emits, or stores it
- [x] Add review notes with the conclusion

### Review
- `z_wr_iss` is not a BannKenn symbol. The repo contains no literal reference to that name, and the server behavior/containment routes only ingest agent payloads and queue containment commands.
- Live process inspection on 2026-03-15 showed `z_wr_iss` as kernel threads (`[z_wr_iss]`) on a host with the `zfs` kernel module loaded and `/home` mounted from a ZFS dataset.
- The heavier BannKenn CPU consumer was `bannkenn-server` itself, with multiple SQLite worker threads active; the likely relationship is server write load causing ZFS write-back activity rather than the server directly "calling" `z_wr_iss`.

# BannKenn vNext — Implementation Plan

## Server CPU / ZFS Pressure Investigation — 2026-03-15
- [x] Capture current runtime signals: top CPU threads, accessible service logs, and likely SQLite-heavy server paths
- [x] Trace the dominant write path in code and confirm the root cause of excess work
- [x] Implement the minimal change that reduces CPU and ZFS write pressure without changing expected behavior
- [x] Verify with targeted tests/runtime checks and add a review summary

### Review
- Live inspection showed the server running inside Docker with SQLite on `/data/bannkenn.db` and a write-ahead log that had grown to roughly `495 MB`, which lined up with the `z_wr_iss` ZFS write-back threads seen in `top`.
- Server-side fixes: limited the SQLite pool to 4 connections, enabled explicit WAL maintenance with startup truncation plus a periodic maintenance task, and rewrote the time-window telemetry queries so they compare directly against RFC3339 cutoffs instead of wrapping `created_at` in `datetime(...)`, allowing the existing timestamp indexes to work.
- The campaign-detection path no longer scans the full `decisions` table to discover already-blocked IPs; it now only looks up the candidate IPs for the current detection batch.
- Dashboard-side fixes: reduced several 10-second polling loops to 30 seconds, slowed the dedicated community page polling to 2 minutes, removed the community-feed summary from the home page’s recurring refresh path, and added a 60-second cache in the dashboard API proxy for `/api/community/feeds`.
- Verification: `cargo fmt --all`, `cargo test -p bannkenn-server`, and `npm run build` all succeeded. After redeploying the containers, the live WAL dropped from roughly `495 MB` to `64 MB`, and the previously repeating `community_feeds` summary query stopped spamming the server logs every ~10 seconds.
- Residual hotspot: startup still performs a full GeoIP-backfill scan over historical `decisions`, which showed as a one-time ~5 second slow query after restart. That is now a restart-time issue rather than a steady-state polling loop.

## Decisions Made
- **Review Mode**: EXPANSION
- **Sensor Architecture**: eBPF unified sensor (Aya crate, Linux 5.8+, root required)
- **Event Model**: New `BehaviorEvent` type (separate from `SecurityEvent`)
- **PID Safety**: eBPF-based PID lifecycle tracking (sched_process_exec/exit hooks)
- **Feature Flags**: `[containment]` config section with enabled, dry_run, throttle_enabled, fuse_enabled, auto_fuse_release_min

## CI Clippy Fix Slice — 2026-03-15
- [x] Remove `clone()` on `Copy` values in the agent scorer path
- [x] Replace cloned single-element slice construction in server behavior ingestion
- [x] Verify `cargo clippy --workspace -- -D warnings`

### Review
- Fixed the originally reported clippy failures in `agent/src/scorer.rs` and `server/src/db/behavior.rs`, then continued through the full workspace lint pass until `cargo clippy --workspace -- -D warnings` succeeded on 2026-03-15.
- Refactored server incident helpers to use typed payload structs instead of oversized positional parameter lists, which resolved the additional `too_many_arguments` findings without weakening lint coverage.
- Replaced repeated long SQL row tuple spellings in `server/src/db/containment.rs` with explicit type aliases so the mapping code stays readable and passes `clippy::type_complexity`.

## Windows Target Build Fix Slice — 2026-03-15
- [x] Make Aya dependencies target-specific so Windows builds do not compile Linux-only crates
- [x] Guard Linux-only eBPF integration points in the agent source
- [x] Verify the release build/check path for `x86_64-pc-windows-msvc` as far as the local toolchain allows

### Review
- Moved `aya` and `aya-log` into Linux-only target dependencies so Windows builds no longer attempt to compile `aya-obj` and its `std::os::fd` usage.
- Gated Aya-specific `Pod` impls, imports, constants, structs, and helper functions behind `target_os = "linux"`, and made `SensorManager::from_config` disable the containment sensor cleanly on non-Linux targets.
- Verified on 2026-03-15 with `cargo fmt --all`, `cargo check -p bannkenn-agent`, `cargo clippy -p bannkenn-agent -- -D warnings`, and `cargo tree -p bannkenn-agent --target x86_64-pc-windows-msvc -e normal` (which no longer includes `aya` on the Windows dependency graph). The runner does not have the Windows stdlib installed, so a real local `--target x86_64-pc-windows-msvc` build was not possible here.

## Agent Update Heartbeat Regression Slice — 2026-03-15
- [x] Make self-update replace the same binary path used by the managed systemd service
- [x] Refresh the systemd unit during self-update before restart
- [x] Verify the updater/service path logic with targeted agent checks

### Review
- The self-updater now resolves the same managed binary path that the systemd unit uses instead of blindly replacing `current_exe()`, so `sudo bannkenn-agent update` no longer drifts away from the background service binary.
- The updater also refreshes `/etc/systemd/system/bannkenn-agent.service` before deciding whether to restart, keeping the service pinned to the same binary/config path that `init` and `connect` use.
- Verified on 2026-03-15 with `cargo fmt --all`, `cargo test -p bannkenn-agent`, and `cargo clippy -p bannkenn-agent -- -D warnings`.

## Phase 1 — eBPF Sensor + File Activity Detection
- [x] Add `aya` and `aya-log` to agent/Cargo.toml
- [x] Create `agent/src/ebpf/mod.rs` — sensor management, ring buffer polling
- [x] Create `agent/src/ebpf/events.rs` — BehaviorEvent struct (pid, exe_path, file_ops, io_rate, etc.)
- [x] Create eBPF programs: fanotify-equivalent file monitoring via tracepoints
- [x] Hook `sched_process_exec` / `sched_process_exit` for PID lifecycle tracking
- [x] Create `agent/src/correlator.rs` — PID-to-process map, event correlation
- [x] Create `agent/src/scorer.rs` — Scorer trait + composite behavior scoring
- [x] Add `[containment]` section to `agent/src/config.rs`
- [x] Implement rename/write counters and anomaly scoring
- [x] Add protected PID allowlist (init, systemd, sshd, agent itself)
- [x] Integration test: simulated mass file rename triggers score > 30

### Phase 1 Execution Slice — 2026-03-14
- [x] Add containment config types and defaults to `agent/src/config.rs`
- [x] Add a `BehaviorEvent` model separate from existing `SecurityEvent`
- [x] Implement a userspace file-activity sensor that can produce `BehaviorEvent`s now
- [x] Add a `/proc`-based lifecycle tracker that surfaces exec/exit-style process transitions for watched roots
- [x] Implement a correlator/scorer pipeline for rename/write bursts and protected PID filtering
- [x] Factor the behavior sensor behind a backend boundary so an Aya/ring-buffer source can replace the userspace poller cleanly
- [x] Vendor `aya`/`aya-log` and add a real Aya loader + ring-buffer backend path that can consume a prebuilt eBPF object
- [x] Add a buildable kernel-side BPF object and loader map population for watched/protected path prefixes
- [x] Auto-detect the repo-local BPF object when it has been built so containment can use Aya without extra config in dev
- [x] Wire Phase 1 behavior monitoring into the agent runtime behind config flags
- [x] Add an integration-style test for mass rename scoring
- [x] Verify with targeted `cargo test -p bannkenn-agent`
- [x] Verify the vendored/offline Cargo path still passes after adding Aya
- [x] Verify the BPF object compiles and exposes the expected tracepoint/map symbols

### Deployment Follow-Up Slice — 2026-03-14
- [x] Make `scripts/build-ebpf.sh` portable enough for source installs on supported Linux hosts
- [x] Install the built BPF object into a stable system path during `scripts/install.sh`
- [x] Teach the Aya loader to auto-discover the installed system object path
- [x] Add installer-side Linux kernel version guardrails for containment prerequisites
- [x] Update operator docs for the new source-install containment artifact path
- [x] Verify the installer/build script changes with targeted local checks

### CI / Release Follow-Up Slice — 2026-03-14
- [x] Teach Linux CI jobs to build the containment BPF object explicitly
- [x] Teach Linux release jobs to publish the BPF object as a release artifact alongside the binary
- [x] Verify the workflow changes are internally consistent with the current release asset naming

### Review
- Implemented a compileable Phase 1 slice in the agent: containment config, a separate behavior-event pipeline, userspace file polling, `/proc`-based process correlation, and composite behavior scoring.
- Tightened the Phase 1 architecture with a lifecycle tracker for watched-root processes and a backend abstraction so the future Aya/ring-buffer path has a clean integration point.
- Added the kernel-side BPF slice in `agent/ebpf/containment.bpf.c`: tracepoints for `sched_process_exec`, `sched_process_exit`, `sys_enter_openat`, `sys_exit_openat`, `sys_enter_write`, `sys_enter_close`, `sys_enter_renameat`, `sys_enter_renameat2`, and `sys_enter_unlinkat`, plus ring-buffer and watched/protected-prefix maps.
- Extended the Aya loader so it populates the kernel prefix maps, auto-detects the repo-local `agent/ebpf/bannkenn-containment.bpf.o` artifact when present, and converts exec/exit ring events into lifecycle hints without disturbing the userspace polling fallback.
- Added `scripts/build-ebpf.sh` and verified on 2026-03-14 that it produces a BTF-enabled object whose symbol table exposes the expected `bk_*` programs and `BK_EVENTS`/`BK_WATCH_ROOTS`/`BK_PROTECTED_ROOTS` maps.
- Verified with `cargo test -p bannkenn-agent`, `./scripts/build-ebpf.sh`, and `readelf` inspection on 2026-03-14: all agent tests passed, and the generated BPF ELF matches the loader contract.
- Closed the source-install/runtime follow-up too: `scripts/build-ebpf.sh` now resolves multiarch include directories and supports custom output paths, `scripts/install.sh` warns on kernel/toolchain gaps and installs the BPF object to `/usr/lib/bannkenn/ebpf/`, and the Aya loader auto-discovers that installed path.
- Verified the deployment follow-up with `bash -n scripts/build-ebpf.sh scripts/install.sh`, `./scripts/build-ebpf.sh --out /tmp/bannkenn-containment-test.bpf.o`, and `cargo test -p bannkenn-agent` on 2026-03-14.
- Extended the release pipeline too: Linux CI now builds the containment BPF object explicitly, Linux release jobs publish matching `bannkenn-containment-linux-*.bpf.o` assets, and the README release-install instructions document where to place them on disk.
- Verified the CI/release follow-up with a naming consistency check across `.github/workflows/release.yml` and `README.md`, plus `git diff --check`, on 2026-03-14.
- Remaining containment follow-up is now the truly missing edge: add an eBPF-aware Docker build path if containerized agent packaging is needed, teach the agent updater to fetch/install the matching `.bpf.o` asset, and exercise actual attachment on a Linux host with root and the needed kernel capabilities.
- Added a first real Phase 2 runtime slice: `agent/src/containment.rs` now owns containment state, upward escalation, 60-second transition dampening for decay, and automatic FUSE release back to THROTTLE/SUSPICIOUS after `auto_fuse_release_min`.
- Added enforcement dispatch in `agent/src/enforcement/`: cgroup/tc backends are explicit dry-run-aware stubs for future work, while the proc backend can already issue `SIGSTOP`/`SIGCONT`/`SIGKILL` through `kill` when dry-run is disabled.
- Wired containment decisions into the main agent loop so behavior events now drive state transitions and enforcement outcomes instead of only emitting “Phase 2 pending” logs.
- Verified the Phase 2 slice with `cargo test -p bannkenn-agent` on 2026-03-14, including new transition/decay tests in `agent/src/containment.rs`.
- Closed the next Phase 2 enforcement gap too: containment config now includes explicit cgroup/tc throttle defaults plus management-channel port exemptions, the runtime passes the configured server heartbeat endpoint into the enforcement dispatcher, `agent/src/enforcement/cgroup.rs` now applies real cgroup v2 `io.max` limits for throttled PIDs, and `agent/src/enforcement/tc.rs` now builds a real HTB throttle plan that keeps SSH plus the configured heartbeat endpoint on the fast lane.
- Verified the enforcement follow-up with `cargo fmt`, `cargo test -p bannkenn-agent`, and `git diff --check` on 2026-03-14, including new unit coverage for cgroup device/`io.max` planning and tc management-channel allowlist command generation.
- Added a first Phase 3 server slice: the server now stores structured behavior events plus containment history/current status in the existing database, exposes `POST/GET /api/v1/behavior_events` and `POST/GET /api/v1/containment`, and adds per-agent read routes for recent behavior events and containment history.
- Wired the agent into that Phase 3 slice too: new upload payloads/outbox variants report behavior batches and containment transitions to the server so the new endpoints are immediately exercised instead of staying dead code.
- Verified the Phase 3 slice with `cargo fmt`, `cargo test -p bannkenn-agent -p bannkenn-server`, and `git diff --check` on 2026-03-14, including new persistence tests in `server/src/db.rs` and a new outbox round-trip test in `agent/src/outbox.rs`.
- Closed the remaining Phase 3 server work too: `server/src/db.rs` now aggregates behavior and containment activity into incident records plus chronological incident timelines, and the server exposes `GET /api/v1/incidents`, `GET /api/v1/incidents/:id`, and `GET /api/v1/alerts`.
- Added cross-agent behavior correlation on normalized reason keys plus watched roots, so matching incidents from multiple agents collapse into one incident summary with correlated agent/root sets and a dedicated administrator alert when the incident becomes fleet-visible.
- Added containment-transition alerts and optional PostgreSQL behavior-event archiving: `BANNKENN_BEHAVIOR_PG_URL` now enables a bootstrapped/indexed `behavior_events_archive` mirror path without replacing the primary SQLite runtime database.
- Verified the Phase 3 completion slice with `cargo fmt`, `cargo test -p bannkenn-server`, `cargo test -p bannkenn-agent -p bannkenn-server`, and `git diff --check` on 2026-03-14, including new incident/correlation coverage in `server/src/db.rs` and PostgreSQL archive bootstrap/record tests in `server/src/behavior_pg.rs`.

## Phase 2 — Containment State Machine + Throttling
- [x] Create `agent/src/containment.rs` — state machine (NORMAL → SUSPICIOUS → THROTTLE → FUSE)
- [x] Mutex-protected transitions with 60s rate limiting
- [x] Create `agent/src/enforcement/mod.rs` — trait + dispatch
- [x] Create `agent/src/enforcement/cgroup.rs` — I/O throttling via cgroups v2
- [x] Create `agent/src/enforcement/tc.rs` — network shaping via tc/netem
- [x] Create `agent/src/enforcement/proc.rs` — process suspend/kill (SIGSTOP/SIGKILL)
- [x] Implement decay paths (FUSE → THROTTLE after auto_fuse_release_min)
- [x] Management channel allowlist (SSH, agent heartbeat exempt from network isolation)
- [ ] Integration test: score > 60 triggers throttle, score > 90 triggers fuse

### Phase 2 Execution Slice — 2026-03-14
- [x] Add a containment coordinator/state machine module wired to `BehaviorEvent`s
- [x] Enforce transition rate limiting so repeated high-score events do not thrash containment state
- [x] Implement fuse decay back to throttle after `auto_fuse_release_min`
- [x] Add enforcement trait/dispatch with dry-run-aware process actions first
- [x] Wire containment decisions into the runtime instead of logging "Phase 2 pending"
- [x] Add targeted tests for state transitions, rate limiting, and fuse decay
- [x] Verify with targeted `cargo test -p bannkenn-agent`

### Phase 2 Enforcement Follow-Up Slice — 2026-03-14
- [x] Add explicit containment config defaults for cgroup/tc throttle rates and management-channel exemptions
- [x] Teach the containment runtime/enforcement dispatcher about the configured heartbeat endpoint so management traffic can stay exempt
- [x] Replace the cgroup v2 I/O throttle stub with a real `io.max` application path for throttled PIDs
- [x] Replace the tc/netem stub with a real host-level tc throttle plan that preserves SSH and heartbeat traffic
- [x] Add focused tests for throttle-plan generation and management-channel allowlist behavior
- [x] Verify with targeted `cargo test -p bannkenn-agent`

## Phase 3 — Server Enhancements
- [x] Add behavior event ingestion endpoint (POST /api/v1/behavior_events)
- [x] Add containment status endpoint (GET/POST /api/v1/containment)
- [x] Add incident aggregation and timeline reconstruction
- [x] Cross-agent behavior correlation
- [x] Administrator alert system (containment level changes)
- [x] Store BehaviorEvents in PostgreSQL with appropriate indexes

### Phase 3 Execution Slice — 2026-03-14
- [x] Add server-side storage and indexes for behavior events in the existing database
- [x] Add `POST /api/v1/behavior_events` and `GET /api/v1/behavior_events`
- [x] Add containment event/history storage plus current-status tracking in the existing database
- [x] Add `POST /api/v1/containment` and `GET /api/v1/containment`
- [x] Add agent-scoped read routes for recent behavior events and containment history
- [x] Wire the agent client/outbox/runtime to upload behavior events and containment transitions
- [x] Add focused DB/client tests for the new Phase 3 contracts
- [x] Verify with targeted agent/server test suites

### Phase 3 Completion Slice — 2026-03-14
- [x] Add incident aggregation tables and timeline storage for behavior/containment activity
- [x] Add incident list/detail API routes with reconstructed timelines
- [x] Correlate matching behavior incidents across multiple agents and surface that in incident summaries
- [x] Add administrator alert storage/routes and emit alerts for containment transitions plus cross-agent incidents
- [x] Add optional PostgreSQL behavior-event archive support with schema/index bootstrap
- [x] Add focused tests for incidents, alerts, cross-agent correlation, and PostgreSQL behavior archiving glue
- [x] Verify with targeted agent/server test suites

## Phase 4 — Dashboard Integration
- [x] Containment status panel (per-host state machine visualization)
- [x] Threat level heatmap across hosts
- [x] Activity timeline with behavior events
- [x] Active throttling events list
- [x] Manual fuse trigger/release controls
- [x] Incident detail view with event timeline

### Phase 4 Execution Slice — 2026-03-14
- [x] Add a scalable server-side operator containment command queue for manual fuse trigger/release requests
- [x] Teach the agent to poll/apply containment operator commands and acknowledge outcomes back to the server
- [x] Expose dashboard proxy routes for containment statuses, incidents, alerts, behavior events, and operator containment actions
- [x] Refactor dashboard home/agent detail UI into smaller feature modules before layering in Phase 4 panels
- [x] Add a fleet containment status panel with per-host state visualization and manual fuse controls
- [x] Add a fleet threat heatmap plus active throttling list driven by containment/incident data
- [x] Add a recent activity timeline that surfaces behavior events, containment changes, and alerts coherently
- [x] Add an incident detail page with reconstructed timeline and link it from the dashboard
- [x] Add focused server tests for containment operator commands and verify dashboard/server builds/tests

### Phase 4 Review — 2026-03-14
- Added a server-side containment action queue plus agent polling/acknowledgement flow for operator-triggered FUSE actions, with history persisted in `containment_actions`.
- Added scalable read APIs needed by the dashboard: direct agent detail reads and global containment event history alongside the existing incident/alert/behavior feeds.
- Moved the new containment tests out of inline source blocks into `server/tests/containment_actions.rs` and `agent/tests/containment.rs` so Phase 4 additions follow the repo’s test-folder rule.
- Refactored the dashboard into feature modules under `dashboard/src/features/monitoring/` with dedicated API/data helper layers, smaller page entrypoints, and reusable containment/timeline/incident components.
- Shipped the full Phase 4 UI surface: fleet containment panel, threat heatmap, active throttling list, unified activity timeline, incidents index/detail views, and manual FUSE trigger/release controls on fleet and agent detail screens.
- Verified with `cargo test -p bannkenn-agent -p bannkenn-server`, `npm ci`, `npm run build` in `dashboard/`, `cargo fmt`, and `git diff --check` on 2026-03-14.

## Deployment
- [ ] Add eBPF build stage to Docker (linux-headers, clang, llvm)
- [x] Feature flags default: enabled=false, dry_run=true, fuse_enabled=false
- [x] Update installer for kernel version check (Linux 5.8+ required)
- [ ] Rollback documentation

## Optional Deployment / Runtime Follow-Up
- [ ] Teach `bannkenn-agent update` to fetch/install the matching `.bpf.o` release asset
- [ ] Add a Dockerized agent build/package path that includes the containment BPF object when containerized agent distribution is needed
- [ ] Exercise real privileged eBPF attachment on a Linux host and document the exact runtime capability requirements
- [ ] Exercise real privileged cgroup/tc containment enforcement on a Linux host and document the exact runtime prerequisites/observed behavior

## Refactor Slice — 2026-03-14
- [x] Split oversized server runtime code into library modules with a thin binary entrypoint
- [x] Split oversized server DB code into focused submodules under `server/src/db/`
- [x] Move server-side tests out of inline source blocks into dedicated files under `server/tests/`
- [x] Keep public interfaces stable so existing routes/behavior compile without downstream churn
- [x] Verify with formatting, server tests, full workspace tests, and diff checks

### Refactor Review — 2026-03-14
- Reworked the server crate into a library-first layout with a thin `server/src/main.rs` entrypoint and grouped runtime code under `server/src/app/`.
- Broke the database layer into focused modules for schema bootstrap, events, whitelist/maintenance, agents, community intelligence, behavior ingestion, containment, incidents, helpers, and shared row types; the `server/src/db.rs` root is now a small module hub.
- Moved server tests into `server/tests/` with a shared `tests/support/` fixture module so future coverage can grow without inflating production source files.
- Verified the refactor with `cargo check -p bannkenn-server`, `cargo test -p bannkenn-server`, `cargo test -p bannkenn-agent -p bannkenn-server`, `cargo fmt`, and `git diff --check` on 2026-03-14.

---

# TODOS.md — Deferred Items

## TODO 1: Honeypot/Canary Directory Support
- **What**: Create decoy directories where any file modification triggers instant FUSE
- **Why**: Zero-latency ransomware detection — no scoring delay needed
- **Effort**: S | **Priority**: P2
- **Depends on**: Phase 1 filesystem monitoring
- **Context**: Place directories like `/var/bannkenn/honeypot/` with tempting names. eBPF watches them; any write = instant Level 3. Unlike scoring, this is deterministic and fast.

## TODO 2: File Integrity Snapshots
- **What**: Hash critical directories on boot, detect changes from known-good baseline
- **Why**: Higher confidence for FUSE triggers; enables post-incident forensics
- **Effort**: M | **Priority**: P2
- **Depends on**: Phase 1 filesystem monitoring
- **Context**: On first boot or on-demand, hash /etc, /usr/bin, etc. Containment engine detects not just "files changed fast" but "files changed from known-good state."

## TODO 3: Process Ancestry Trees
- **What**: Walk /proc/<pid>/status to build full parent chain for suspicious processes
- **Why**: Instant "how did this start?" context in dashboard incident view
- **Effort**: S | **Priority**: P2
- **Depends on**: Phase 1 eBPF process correlator
- **Context**: Display chains like bash → curl → python3 → ransomware.py in incident views. Every EDR shows these for good reason.

## TODO 4: "What Would Have Happened" Dry-Run Replay
- **What**: Replay historical events against current scoring config to show when containment would have triggered
- **Why**: Solves #1 adoption barrier — lets admins tune thresholds without risking production
- **Effort**: M | **Priority**: P3
- **Depends on**: Phase 2 scoring engine + event logging
- **Context**: Admins can replay logged events and see "Level 2 would have triggered at 14:32:07, FUSE at 14:32:41." Builds confidence before enabling enforcement.

## TODO 5: Per-Directory Canary Files
- **What**: Place hidden sentinel files (.bannkenn_canary) in protected directories
- **Why**: Catches in-place encryption that honeypot dirs miss
- **Effort**: S | **Priority**: P2
- **Depends on**: Phase 1 filesystem monitoring
- **Context**: Complements honeypot dirs (TODO 1). Honeypots catch broad scanning; canary files catch targeted in-place encryption. Any modification/deletion = instant FUSE.
