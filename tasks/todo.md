# Tasks

## Source
- Based on `docs/06_BannKenn v2 Detection Design Review.md`

## Immediate Fixes
- [ ] Stop repeated polling of `/var/log/auth.log` on hosts that use journald; prefer journal subscriptions and suppress missing-file warning spam.
- [ ] Lower the default sensitivity for rename burst and delete burst scoring, then back the new thresholds with regression coverage.
- [ ] Exclude `bannkenn-agent`, BannKenn-managed state paths, and internal sync/policy work from behavioral scoring.
- [ ] Record executable path, parent process, and enough event context on every flagged detection to explain why it fired.
- [ ] Seed default trust exceptions or policy entries for `fwupd`, `snapd`, `apt`, `dpkg`, `systemd`, and related maintenance processes.
- [ ] Deduplicate repeated alerts so one root cause does not flood the dashboard or logs.

## Phase 1: Stabilization
- [ ] Reduce agent CPU usage with batching, bounded queues, caching, debounce windows, and backpressure instead of high-frequency polling.
- [ ] Replace repeated identical warning paths with rate-limited or coalesced warnings.
- [ ] Verify the agent cannot become the top CPU consumer during an event storm.

## Phase 2: Attribution And Trust
- [ ] Enrich collected events with PID, PPID, executable path, command line, UID/GID, timestamp, operation type, target path, rename extension changes, bytes written, and host/container context.
- [ ] Build a process identity profile that tracks executable path, package owner, parent chain, service unit, first-seen time, and known-good classification.
- [ ] Introduce a trust model with clear classes such as trusted system process, trusted package-managed process, allowed local process, unknown process, and suspicious process.
- [ ] Add a policy-driven allowlist/baseline layer keyed by executable path, package name, service unit, container image, and maintenance window.
- [ ] Identify package-manager and systemd-maintenance activity explicitly so protected-path changes can be downgraded when context is trustworthy.

## Phase 3: Correlation And Scoring
- [ ] Replace rule-only classification with weighted scoring across path sensitivity, trust level, burst size, write volume, extension anomaly, directory spread, parent reputation, recurrence, and container relevance.
- [ ] Correlate low-level events into behavior chains instead of treating small isolated bursts as strong indicators by themselves.
- [ ] Add severity bands such as observed, suspicious, high risk, and containment candidate with tunable environment profiles.
- [ ] Require multi-signal correlation for ransomware-style alerts, including unknown process identity, meaningful rename bursts, repeated writes, and user/application data targeting without maintenance context.

## Phase 4: Advanced Detection
- [ ] Add entropy or unreadability indicators for rewritten files to improve ransomware confidence.
- [ ] Add container-aware attribution for container ID, image name, orchestrator metadata, and bind-mount or volume context.
- [ ] Gate containment actions behind higher-confidence scoring so weak signals do not trigger disruptive response.
- [ ] Support fleet-wide baseline or trust sharing once local attribution and scoring are stable.

## Verification
- [ ] Run package-update, `fwupd`, `snapd`, and unattended-upgrade scenarios and prove the new model reduces false positives on protected paths.
- [ ] Benchmark before/after CPU usage under normal load and during synthetic event storms.
- [ ] Validate journald-first behavior on systemd hosts and confirm sane fallback on legacy log-file setups.
- [ ] Simulate ransomware-like rename/write workloads and compare alert quality against the current detector.
- [ ] Document the default trust seeds, tuning knobs, and operator-facing severity semantics.

## Review
- The design review points to false positives and CPU cost as the first issues to fix; stabilization and attribution should land before advanced ransomware heuristics.
- The core architectural gap is weak process attribution, so scoring changes should depend on richer event context rather than threshold tuning alone.
- Self-noise suppression and maintenance-aware trust are required for operator trust; they should be treated as product correctness work, not optional polish.
