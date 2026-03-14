# BannKenn vNext — Implementation Plan

## Decisions Made
- **Review Mode**: EXPANSION
- **Sensor Architecture**: eBPF unified sensor (Aya crate, Linux 5.8+, root required)
- **Event Model**: New `BehaviorEvent` type (separate from `SecurityEvent`)
- **PID Safety**: eBPF-based PID lifecycle tracking (sched_process_exec/exit hooks)
- **Feature Flags**: `[containment]` config section with enabled, dry_run, throttle_enabled, fuse_enabled, auto_fuse_release_min

## Phase 1 — eBPF Sensor + File Activity Detection
- [ ] Add `aya` and `aya-log` to agent/Cargo.toml
- [ ] Create `agent/src/ebpf/mod.rs` — sensor management, ring buffer polling
- [x] Create `agent/src/ebpf/events.rs` — BehaviorEvent struct (pid, exe_path, file_ops, io_rate, etc.)
- [ ] Create eBPF programs: fanotify-equivalent file monitoring via tracepoints
- [ ] Hook `sched_process_exec` / `sched_process_exit` for PID lifecycle tracking
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
- [x] Implement a correlator/scorer pipeline for rename/write bursts and protected PID filtering
- [x] Wire Phase 1 behavior monitoring into the agent runtime behind config flags
- [x] Add an integration-style test for mass rename scoring
- [x] Verify with targeted `cargo test -p bannkenn-agent`

### Review
- Implemented a compileable Phase 1 slice in the agent: containment config, a separate behavior-event pipeline, userspace file polling, `/proc`-based process correlation, and composite behavior scoring.
- Verified with `cargo test -p bannkenn-agent` on 2026-03-14: all agent tests passed, including the new mass-rename regression.
- Remaining Phase 1 gaps are the true Aya/eBPF pieces: vendored `aya` dependencies, kernel probes/tracepoints, and PID lifecycle hooks from `sched_process_exec/exit`.

## Phase 2 — Containment State Machine + Throttling
- [ ] Create `agent/src/containment.rs` — state machine (NORMAL → SUSPICIOUS → THROTTLE → FUSE)
- [ ] Mutex-protected transitions with 60s rate limiting
- [ ] Create `agent/src/enforcement/mod.rs` — trait + dispatch
- [ ] Create `agent/src/enforcement/cgroup.rs` — I/O throttling via cgroups v2
- [ ] Create `agent/src/enforcement/tc.rs` — network shaping via tc/netem
- [ ] Create `agent/src/enforcement/proc.rs` — process suspend/kill (SIGSTOP/SIGKILL)
- [ ] Implement decay paths (FUSE → THROTTLE after auto_fuse_release_min)
- [ ] Management channel allowlist (SSH, agent heartbeat exempt from network isolation)
- [ ] Integration test: score > 60 triggers throttle, score > 90 triggers fuse

## Phase 3 — Server Enhancements
- [ ] Add behavior event ingestion endpoint (POST /api/v1/behavior_events)
- [ ] Add containment status endpoint (GET/POST /api/v1/containment)
- [ ] Add incident aggregation and timeline reconstruction
- [ ] Cross-agent behavior correlation
- [ ] Administrator alert system (containment level changes)
- [ ] Store BehaviorEvents in PostgreSQL with appropriate indexes

## Phase 4 — Dashboard Integration
- [ ] Containment status panel (per-host state machine visualization)
- [ ] Threat level heatmap across hosts
- [ ] Activity timeline with behavior events
- [ ] Active throttling events list
- [ ] Manual fuse trigger/release controls
- [ ] Incident detail view with event timeline

## Deployment
- [ ] Add eBPF build stage to Docker (linux-headers, clang, llvm)
- [ ] Feature flags default: enabled=false, dry_run=true, fuse_enabled=false
- [ ] Update installer for kernel version check (Linux 5.8+ required)
- [ ] Rollback documentation

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
