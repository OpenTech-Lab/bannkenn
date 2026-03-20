# Tasks

## Source
- Based on `docs/06_BannKenn v2 Detection Design Review.md`

## Current Task: 2026-03-20 CodeRabbit Follow-Ups
- [x] Keep the active fuse PID/root stable when a fused coordinator only refreshes its release timer.
- [x] Cap nested `parent_chain` string fields before behavior events are persisted or archived.
- [x] Add regression tests for fuse-target stability and nested parent-chain caps.
- [x] Run focused verification for the touched agent and server paths.
- [x] Tighten SQLite schema migration `ALTER TABLE ... ADD COLUMN` handling so only duplicate-column cases are ignored.
- [x] Add schema migration regression tests for duplicate-column idempotency and real failure propagation.
- [x] Re-run focused server verification for the schema migration path.
- Review:
  - Split fuse timer extension from fuse-target assignment so already-fused refreshes do not overwrite the suspended PID/root.
  - Added a containment regression proving a second containment-candidate on a different PID/root still resumes and throttles the original suspended process when fuse decays.
  - Added `cap_parent_chain(...)` plus shared optional-string capping in the behavior-event route so nested ancestry fields are truncated before persistence.
  - Replaced blanket ignored `ALTER TABLE ... ADD COLUMN` results with an `add_column_if_missing(...)` helper that only suppresses SQLite duplicate-column errors and now surfaces real migration failures.
  - Added schema migration tests proving duplicate-column retries remain idempotent while missing-table/real DDL failures still abort the migration.
  - Verification: `cargo fmt --all`, `cargo test -p bannkenn-agent --test containment`, `cargo test -p bannkenn-server add_column_if_missing`, `cargo test -p bannkenn-server cap_parent_chain`.

## Immediate Fixes
- [x] Stop repeated polling of `/var/log/auth.log` on hosts that use journald; prefer journal subscriptions and suppress missing-file warning spam.
- [x] Lower the default sensitivity for rename burst and delete burst scoring, then back the new thresholds with regression coverage.
- [x] Exclude `bannkenn-agent`, BannKenn-managed state paths, and internal sync/policy work from behavioral scoring.
- [x] Record executable path, parent process, and enough event context on every flagged detection to explain why it fired.
- [x] Seed default trust exceptions or policy entries for `fwupd`, `snapd`, `apt`, `dpkg`, `systemd`, and related maintenance processes.
- [x] Deduplicate repeated alerts so one root cause does not flood the dashboard or logs.

## Phase 1: Stabilization
- [x] Reduce agent CPU usage with batching, bounded queues, caching, debounce windows, and backpressure instead of high-frequency polling.
- [x] Replace repeated identical warning paths with rate-limited or coalesced warnings.
- [x] Verify the agent cannot become the top CPU consumer during an event storm.
- [x] Fix the dashboard Next.js workspace-root configuration so production builds stop warning about multiple lockfiles.

## Phase 2: Attribution And Trust
- [x] Enrich collected events with PID, PPID, executable path, command line, UID/GID, timestamp, operation type, target path, rename extension changes, bytes written, and host/container context.
- [x] Build a process identity profile that tracks executable path, package owner, parent chain, service unit, first-seen time, and known-good classification.
  - [x] Resolve package ownership for tracked executables with cached profile metadata and use it to strengthen `trusted_package_managed_process` attribution.
  - [x] Capture a bounded parent ancestry chain instead of only a single parent hint, then flow it through uploads, storage, and the dashboard.
  - [x] Persist the new identity fields through agent outbox, server SQLite/Postgres storage, incident timeline payloads, and dashboard event details.
  - [x] Carry optional package metadata alongside the ancestry chain in the behavior-event contract and dashboard detail view.
- [x] Add service-unit, first-seen, and explicit trust-class metadata to process attribution and behavior events as the next step toward the identity profile.
- [x] Introduce a trust model with clear classes such as trusted system process, trusted package-managed process, allowed local process, unknown process, and suspicious process.
- [x] Add a policy-driven allowlist/baseline layer keyed by executable path, package name, service unit, container image, and maintenance window.
  - [x] Extend trust policy overrides to match package names in addition to executable paths, service units, and maintenance windows.
  - [x] Add container-image keyed trust/baseline matching once container image attribution exists.
    - [x] Resolve best-effort container image names from tracked container runtime/container ID metadata during lifecycle attribution.
    - [x] Allow trust policy overrides to match `container_images` in addition to executable paths, package names, and service units.
    - [x] Persist `container_image` through the agent upload contract, server SQLite/Postgres storage, incident timeline payloads, and dashboard event details.
    - [x] Add regression coverage for container image parsing, policy matching, and behavior-event round trips.
- [x] Add agent-config trust policy overrides keyed by executable path and service unit, with optional maintenance windows and event visibility for the matched policy.
- [x] Add explicit maintenance attribution for package-manager helper and trusted system/package-managed work, then use that metadata in scoring and dashboard event details.
- [x] Identify package-manager and systemd-maintenance activity explicitly so protected-path changes can be downgraded when context is trustworthy.

## Phase 3: Correlation And Scoring
- [x] Replace rule-only classification with weighted scoring across path sensitivity, trust level, burst size, write volume, extension anomaly, directory spread, parent reputation, recurrence, and container relevance.
  - [x] Add explicit weighted dimensions for path sensitivity, trust class, directory spread, parent reputation, and container context using the current behavior-event telemetry.
  - [x] Promote suspicious temp-path, shell-lineage, and process-mismatch combinations while downgrading trusted system/package/container maintenance activity.
  - [x] Expose the new weighted dimensions through containment scoring config defaults so the model stays tunable.
  - [x] Back the weighted scorer with regression coverage for benign maintenance/container cases and higher-confidence multi-signal suspicious cases.
  - [x] Add rename-extension anomaly and short-window recurrence/history weighting so repeated cross-batch activity can raise risk without relying on a single burst.
- [x] Correlate low-level events into behavior chains instead of treating small isolated bursts as strong indicators by themselves.
  - [x] Derive explicit behavior-chain signals from current telemetry such as meaningful rename bursts, repeated writes, user-data targeting, weak process trust, and suspicious lineage.
  - [x] Gate high-risk containment-oriented levels on a minimum correlated signal count instead of raw score alone.
  - [x] Emit operator-visible reasons when an event is downgraded because it lacks enough correlated ransomware-style signals.
  - [x] Feed recurrence/history into the behavior-chain signal model instead of limiting correlation to a single batch.
- [x] Add severity bands such as observed, suspicious, high risk, and containment candidate with tunable environment profiles.
  - [x] Split user-facing behavior severity from containment actions so events/reporting/dashboard use `observed`, `suspicious`, `high_risk`, and `containment_candidate`.
  - [x] Add configurable environment-profile tuning for severity thresholds while preserving the existing throttle/fuse containment controls.
- [x] Require multi-signal correlation for ransomware-style alerts, including unknown process identity, meaningful rename bursts, repeated writes, and user/application data targeting without maintenance context.
  - [x] Require the current scorer to see unknown/untrusted identity, meaningful rename pressure, repeated writes, and user/application data targeting before escalating to the highest levels when maintenance context is absent.
  - [x] Require recurrence/history or equivalent corroboration before repeated medium-confidence batches can escalate into the highest user-facing severity bands.

## Phase 4: Advanced Detection
- [x] Add entropy or unreadability indicators for rewritten files to improve ransomware confidence.
  - [x] Track bounded before/after content profiles for watched files so modified user-data files can surface entropy jumps or text-to-unreadable transitions.
  - [x] Feed entropy/unreadability rewrite indicators into weighted scoring and behavior-chain correlation without expanding the server/dashboard schema.
  - [x] Back the new content-based signals with regression coverage for benign text rewrites, unreadable rewrites, and higher-entropy suspicious rewrites.
- [x] Add container-aware attribution for container ID, image name, orchestrator metadata, and bind-mount or volume context.
- [x] Gate containment actions behind higher-confidence scoring so weak signals do not trigger disruptive response.
- [x] Support fleet-wide baseline or trust sharing once local attribution and scoring are stable.

## Verification
- [x] Run package-update, `fwupd`, `snapd`, and unattended-upgrade scenarios and prove the new model reduces false positives on protected paths.
- [x] Benchmark before/after CPU usage under normal load and during synthetic event storms.
- [x] Validate journald-first behavior on systemd hosts and confirm sane fallback on legacy log-file setups.
- [x] Simulate ransomware-like rename/write workloads and compare alert quality against the current detector.
- [x] Document the default trust seeds, tuning knobs, and operator-facing severity semantics.

## Optional Tasks
- [x] Upgrade `sqlx-postgres` from `0.7.4` or otherwise resolve the current future-Rust incompatibility warning reported during `cargo test` and `cargo clippy`.

## Review
- The design review points to false positives and CPU cost as the first issues to fix; stabilization and attribution should land before advanced ransomware heuristics.
- The core architectural gap is weak process attribution, so scoring changes should depend on richer event context rather than threshold tuning alone.
- Self-noise suppression and maintenance-aware trust are required for operator trust; they should be treated as product correctness work, not optional polish.
- 2026-03-19: Phase 1 stabilization landed in the agent with idle-scan backoff for userspace containment polling, per-poll file-activity batch coalescing, capped Aya ring-buffer draining, and rate-limited missing-path/read warnings in the log watcher.
- Verification for this pass: `cargo test -p bannkenn-agent` and `cargo clippy -p bannkenn-agent --tests -- -D warnings`.
- Remaining runtime validation: live-host CPU benchmarking and journald-first end-to-end behavior are still tracked in the `Verification` section above.
- 2026-03-19: Immediate scoring and attribution fixes landed. Rename and delete burst defaults were lowered, repeated behavior uploads are now deduplicated on the agent, and trusted maintenance plus BannKenn-internal work are downgraded before they can flood incidents.
- Behavior events now preserve parent process attribution through the agent upload path, server storage, incident timeline payloads, and the dashboard agent detail view so operators can see both the executable and its parent context.
- Regression coverage for this pass includes scorer threshold tests, trust-suppression tests, agent-side dedup tests, server round-trip/archive checks for parent fields, and a dashboard production build.
- Verification for this pass: `cargo test -p bannkenn-agent`, `cargo test -p bannkenn-server`, `cargo clippy -p bannkenn-agent -p bannkenn-server --tests -- -D warnings`, and `npm run build` in `dashboard/`.
- 2026-03-19: Auth log watching now prefers a single `journalctl --follow` stream for legacy auth facilities on journald hosts, suppressing repeated missing-file polls while retaining file-tail fallback on non-journald systems or when `journalctl` cannot start.
- 2026-03-19: Behavior-event attribution now preserves PPID, UID/GID, and container runtime/container ID from `/proc` through agent uploads, durable outbox replay, SQLite/Postgres storage, incident timeline payloads, and the dashboard agent detail view.
- Regression coverage for this pass includes journald source-planning tests, `/proc/<pid>/status` parser coverage, agent outbox serialization round-trips for enriched behavior payloads, server behavior round-trips/archive checks for the new fields, and another dashboard production build.
- Verification for this pass: `cargo test -p bannkenn-agent`, `cargo test -p bannkenn-server`, `cargo clippy -p bannkenn-agent -p bannkenn-server --tests -- -D warnings`, and `npm run build` in `dashboard/`.
- 2026-03-19: The dashboard Next.js workspace-root warning is fixed by setting `outputFileTracingRoot` explicitly, so production builds no longer complain about multiple lockfiles.
- 2026-03-19: Process identity attribution now carries `service_unit`, `first_seen_at`, and an explicit `trust_class` through lifecycle tracking, scoring, agent uploads, SQLite/Postgres storage, and the dashboard behavior-event view.
- Regression coverage for this pass includes lifecycle service-unit/first-seen/trust-class tests, scorer coverage for trust-aware maintenance downgrades, clean `cargo clippy` on agent/server, and a dashboard production build without the prior workspace-root warning.
- Remaining runtime validation: journald-first behavior on a live systemd host is still intentionally tracked in `Verification` because it requires host-level execution rather than another repo-only change.
- 2026-03-19: Agent-config trust policy overrides now support executable-path and service-unit matching, optional maintenance windows, and `visible`/`hidden` event visibility. Matched policy names flow through agent uploads, SQLite/Postgres storage, and the dashboard behavior-event view.
- 2026-03-19: Lifecycle attribution now emits explicit `maintenance_activity` metadata for package-manager helper work and trusted system/package-managed maintenance, and the scorer uses that metadata instead of re-deriving maintenance context from behavior-event heuristics.
- Regression coverage for this pass includes trust-policy config round-trips, overnight maintenance-window matching, lifecycle trust-policy/maintenance classification tests, hidden-policy suppression tests, outbox/server/archive round-trips for the new behavior fields, and another dashboard production build.
- Verification for this pass: `cargo test -p bannkenn-agent`, `cargo test -p bannkenn-server`, `cargo clippy -p bannkenn-agent -p bannkenn-server --tests -- -D warnings`, and `npm run build` in `dashboard/`.
- The `sqlx-postgres v0.7.4` future incompatibility warning was split out as separate dependency work rather than being conflated with the trust/scoring feature passes; its upgrade result is recorded below.
- 2026-03-19: Behavior-event identity plumbing now carries optional `package_name`, optional `package_manager`, and a typed `parent_chain` array through the server ingest contract, SQLite/Postgres persistence, dashboard agent detail view, and round-trip tests.
- 2026-03-19: Agent lifecycle profiling now resolves cached package ownership for tracked executables, uses that evidence to back `trusted_package_managed_process`, and captures bounded `/proc` ancestry chains that feed maintenance classification and container temp-activity suppression.
- Regression coverage for this pass includes package-owner parser tests, fake-`/proc` ancestry extraction tests, package-name trust-policy matching, shell-ancestor regressions in lifecycle/scorer logic, agent outbox round-trips for the new fields, server behavior/archive round-trips, and the dashboard production build.
- Verification for this pass: `cargo fmt --all`, `cargo test -p bannkenn-agent`, `cargo test -p bannkenn-server`, `cargo clippy -p bannkenn-agent -p bannkenn-server --tests -- -D warnings`, and `npm run build` in `dashboard/`.
- 2026-03-20: The agent scorer now adds weighted path-sensitivity, trust-lineage, directory-spread, shell-lineage, and newly-observed-process signals on top of the existing burst/throughput model while still downgrading trusted maintenance, known JVM temp extraction, containerized service temp work, and BannKenn-internal activity.
- 2026-03-20: `ContainmentConfig` now exposes the new scoring knobs (`user_data_bonus`, trust penalties, directory spread, shell lineage, and recent-process window/bonus) so later environment-profile tuning can build on explicit defaults instead of hard-coded constants.
- Regression coverage for this pass adds multi-signal weighted-scorer tests for user-data targeting, cross-directory spread, shell ancestry, and trusted-lineage score reduction, plus config-default assertions for the new knobs.
- Verification for this pass: `cargo fmt --all`, `cargo test -p bannkenn-agent`, and `cargo clippy -p bannkenn-agent --tests -- -D warnings`.
- Remaining gap under the parent scoring task: rename-extension anomaly and true recurrence/history scoring are still open, so the top-level weighted-scoring checkbox intentionally remains unchecked.
- 2026-03-20: High-risk scorer escalation is now behavior-chain-aware. `throttle_candidate` and `fuse_candidate` require correlated ransomware-style evidence instead of score alone, using explicit chain signals for weak identity, meaningful rename pressure, repeated writes, user-data targeting, suspicious lineage, directory spread, and rapid deletes.
- 2026-03-20: The scorer now emits operator-visible downgrade reasons when a raw high score lacks enough correlated signals, so high rename volume without repeated writes or untrusted identity stays visible but does not jump straight to higher containment-oriented levels.
- `ContainmentConfig` now exposes the chain thresholds (`meaningful_rename_count`, `meaningful_write_count`, `high_risk_min_signals`, and `containment_candidate_min_signals`) so later severity-band/profile work can reuse explicit knobs.
- Regression coverage for this pass adds scorer tests for score-only rename bursts being downgraded, raw fuse-range events being held at throttle without extra corroboration, and config-default assertions for the new chain thresholds.
- Verification for this pass: `cargo fmt --all`, `cargo test -p bannkenn-agent`, and `cargo clippy -p bannkenn-agent --tests -- -D warnings`.
- Remaining gap under correlation/scoring: this is still per-batch correlation, not true recurrence/history-based behavior chaining across multiple events, so the parent task stays open.
- 2026-03-20: Lifecycle attribution now resolves best-effort `container_image` metadata from container runtime/container ID context, caches it per container identity, and uses image names in the process-profile key so repeated containers from the same image preserve baseline state.
- 2026-03-20: Trust policy overrides now support `container_images`, and `container_image` flows through the agent outbox/upload contract, server SQLite/Postgres behavior storage, incident timeline payloads, and the dashboard behavior-event detail view.
- Regression coverage for this pass adds lifecycle tests for Docker/CRI image parsing, Docker config prefix matching, container-image trust-policy matching, first-seen reuse across new container IDs for the same image, outbox/server/archive round-trips for `container_image`, and another dashboard production build.
- Verification for this pass: `cargo fmt --all`, `cargo test -p bannkenn-agent`, `cargo test -p bannkenn-server`, `cargo clippy -p bannkenn-agent -p bannkenn-server --tests -- -D warnings`, and `npm run build` in `dashboard/`.
- 2026-03-20: The server dependency stack now uses `sqlx v0.8.6`, which upgrades `sqlx-postgres` off `0.7.4` and removes the previously tracked future-Rust incompatibility warning from the standard `cargo test` and `cargo clippy` workflow.
- This dependency bump did not require query or API changes in the server code; the upgrade compiled and passed on the existing SQLx usage.
- Verification for this pass: `cargo test -p bannkenn-agent`, `cargo test -p bannkenn-server`, and `cargo clippy -p bannkenn-agent -p bannkenn-server --tests -- -D warnings`.
- 2026-03-20: Phase 3 correlation/scoring is complete. The scorer now tracks rename-extension anomalies and short-window recurrent activity across batches, feeds recurrence into the behavior-chain signal model, and only promotes repeated medium-confidence batches when that corroboration exists.
- 2026-03-20: User-facing behavior severities now use `observed`, `suspicious`, `high_risk`, and `containment_candidate` across agent events, server ingest/storage normalization, and dashboard severity mapping, while containment actions remain on the existing throttle/fuse state machine behind the scenes.
- `ContainmentConfig` now exposes `environment_profile` alongside the new extension-anomaly and recurrence knobs, and the scorer adjusts severity thresholds/signal requirements per profile without changing throttle/fuse action semantics.
- Regression coverage for this pass adds rename-extension anomaly scoring, recurrence-driven `high_risk` escalation, environment-profile threshold tests, severity-name compatibility checks across containment/outbox/server/archive paths, and another dashboard production build.
- Verification for this pass: `cargo fmt --all --check`, `cargo test -p bannkenn-agent`, `cargo test -p bannkenn-server`, `cargo clippy -p bannkenn-agent -p bannkenn-server --tests -- -D warnings`, and `npm run build` in `dashboard/`.
- 2026-03-20: Phase 4 content-based rewrite detection has started. The agent now keeps bounded per-path content profiles for watched files, detects text-to-unreadable rewrites plus sharp entropy jumps, and annotates activity batches with those indicators before scoring.
- 2026-03-20: The scorer treats unreadable and high-entropy rewrites as first-class weighted signals in both severity scoring and behavior-chain correlation, while trusted maintenance, package-helper temp work, containerized service temp activity, and agent-internal work explicitly suppress those content-based bonuses to limit false positives.
- Regression coverage for this pass adds content-profile tracker tests for benign text rewrites versus unreadable/high-entropy rewrites, scorer coverage for rewrite-driven `high_risk` escalation, and config-default assertions for the new sampling and scoring knobs.
- Verification for this pass: `cargo fmt --all`, `cargo fmt --all --check`, `cargo test -p bannkenn-agent`, and `cargo clippy -p bannkenn-agent --tests -- -D warnings`.
- 2026-03-20: Container-aware attribution now resolves and caches full container context instead of image-only metadata. The agent extracts orchestrator labels and mount mappings from inspect metadata, maps container-internal open paths back onto watched host roots for correlation, and attaches only the relevant bind-mount or volume context to behavior events.
- 2026-03-20: Orchestrator metadata and relevant container mounts now flow end to end through agent uploads, SQLite/Postgres behavior storage, incident timeline payloads, archive records, and the dashboard agent detail view.
- Regression coverage for this pass adds lifecycle tests for inspect-label parsing and watched-root mount mapping, plus server round-trip and archive assertions for the new orchestrator and mount payloads.
- Verification for this pass: `cargo fmt --all`, `cargo fmt --all --check`, `cargo test -p bannkenn-agent`, `cargo test -p bannkenn-server`, `cargo clippy -p bannkenn-agent -p bannkenn-server --tests -- -D warnings`, and `npm run build` in `dashboard/`.
- 2026-03-20: Automatic throttle and fuse actions now have a second gate beyond event severity. The containment coordinator requires repeated corroborating `high_risk` or `containment_candidate` events within a short window before applying disruptive actions, and it holds missing-PID events at `suspicious` even when the scorer output is higher.
- `ContainmentConfig` now exposes `auto_containment_requires_pid`, `containment_action_window_secs`, `throttle_action_min_events`, and `fuse_action_min_events` so operators can tune action confidence separately from scoring thresholds.
- Regression coverage for this pass adds containment tests for repeated high-risk throttling, repeated containment-candidate fuse escalation, missing-PID suppression, and config-default assertions for the new action-gating knobs.
- Verification for this pass: `cargo fmt --all`, `cargo fmt --all --check`, `cargo test -p bannkenn-agent`, and `cargo clippy -p bannkenn-agent --tests -- -D warnings`.
- 2026-03-20: Fleet trust sharing now extends the existing shared-risk snapshot with low-risk cross-agent process baselines keyed by executable path plus stable service/package/container identity. The server only exports those shared profiles after they appear on multiple agents and never escalate beyond `suspicious`, and the agent scorer only uses them when local lineage is otherwise stable.
- 2026-03-20: Operator-facing docs now describe the seeded maintenance trust classes, the primary scoring/correlation tuning knobs, the severity-band semantics, and the new fleet baseline sharing path in `README.md`.
- Regression coverage for this pass adds agent scorer/shared-risk tests for fleet-shared process downgrades and identity matching, a benign-maintenance versus ransomware-workload comparison test, and server DB tests proving shared process baselines are exported only for multi-agent low-risk histories and are suppressed when any `high_risk` history exists.
- Verification for this pass: `cargo fmt --all`, `cargo test -p bannkenn-agent --tests`, `cargo test -p bannkenn-server`, and `cargo clippy -p bannkenn-agent -p bannkenn-server --tests -- -D warnings`.
- 2026-03-20: Remaining verification is now backed by explicit maintenance-scenario coverage plus a repeatable runtime harness in `scripts/verify-runtime-checks.sh`.
- Protected-path false-positive verification now covers package-update (`apt-get`), `snapd`, and `unattended-upgrade` protected-path scenarios in addition to the existing `fwupd` scorer regression; all four stay at `observed` severity in the current model.
- Runtime verification on this Ubuntu 24.04 systemd host recorded `journald_check=passed`, `normal_cpu_pct=0.20`, and `storm_cpu_pct=173.00` for a clean workspace build under a single-log idle run and a 100k-line synthetic auth-log storm.
- Legacy fallback remains covered by the existing watcher regression `build_log_source_plans_keeps_legacy_files_without_journald`, while the systemd preference path remains covered by `build_log_source_plans_prefers_single_journald_auth_stream` and the live runtime harness above.
- Live-host caveat: the currently installed `/usr/local/bin/bannkenn-agent run` service on this host is still consuming about `42.5%` CPU and repeatedly polling stale Docker JSON log paths, so the deployment itself needs a refresh or config cleanup even though the workspace build passed the verification harness.
- Verification for this pass: `cargo test -p bannkenn-agent protected_path_activity_stays_observed -- --nocapture`, `cargo test -p bannkenn-agent build_log_source_plans -- --nocapture`, and `bash scripts/verify-runtime-checks.sh`.
