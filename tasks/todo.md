# tasks

## Done: Wire relocated `agent/tests/unit` files into Cargo test binaries

### Scope
- [x] Record the review correction about orphaned relocated tests
- [x] Add top-level `agent/tests/unit.rs` and `agent/tests/main_unit.rs` manifests for the relocated library and binary test trees
- [x] Verify Cargo discovers and runs the new test binaries cleanly
- [x] Re-run workspace tests after the wiring change

### Notes
- Review correction: moving test source files under `agent/tests/unit/**` was not sufficient by itself; Cargo still needed a top-level integration-test entrypoint to discover that tree directly.
- Keep the relocated test files in place and add explicit test-binary wiring instead of moving them back into `agent/src`.

### Review
- Added [agent/tests/unit.rs](/home/toyofumi/Project/Bannkenn/agent/tests/unit.rs) to compile the relocated library-side test tree under the same crate shape as `src/lib.rs`.
- Added [agent/tests/main_unit.rs](/home/toyofumi/Project/Bannkenn/agent/tests/main_unit.rs) to do the same for the binary-side test tree rooted at `src/main.rs`.
- Direct verification: `cargo test -p bannkenn-agent --test unit` passed.
- Direct verification: `cargo test -p bannkenn-agent --test main_unit` passed.
- Workspace verification: `cargo clippy --workspace -- -D warnings` passed.
- Workspace verification: `cargo test --workspace` passed.

## Done: Move `agent` test code under `agent/tests`

### Scope
- [x] Audit the current partial test relocation state in `agent/src`
- [x] Move the remaining inline test modules under `agent/tests/unit`
- [x] Keep `agent/src` modules wired to external test files with `#[path = ...]`
- [x] Re-run formatting, clippy, and workspace tests after the refactor

### Notes
- Goal: keep unit-test visibility and behavior unchanged while physically storing test code under `agent/tests`.
- The earlier bulk move already relocated most `agent/src` test modules; the remaining inline modules are the pattern detectors under `agent/src/patterns/`.

### Review
- Moved the remaining `agent/src/patterns/*.rs` inline `mod tests` blocks into `agent/tests/unit/patterns/*_tests.rs`.
- Removed the last test-only helper from `agent/src/enforcement/cgroup.rs` and defined it in `agent/tests/unit/enforcement/cgroup_tests.rs` so `agent/src` only keeps `#[cfg(test)] #[path = ...] mod tests;` stubs.
- Verification: `cargo fmt --all` passed.
- Verification: `cargo clippy --workspace -- -D warnings` passed.
- Verification: `cargo test --workspace` passed.

## Done: Malware-specific trigger follow-up from 15.6 review

### Scope
- [x] Add temp-write followed by `execve` detection for the same temp path
- [x] Add process-name / executable-path mismatch weighting for masquerade detection
- [x] Add regression coverage for both new triggers
- [x] Re-review the remaining 15.6 gaps after implementation

### Notes
- Review correction: only the temp-path executable bonus was implemented; the rest of 15.6 was still missing.
- Current target: ship the two highest-signal triggers the existing lifecycle model can support cleanly without inventing network or persistence telemetry.
- Remaining 15.6 gaps after this patch: temp-write followed by outbound network, persistence after temp staging, and miner command-line / stratum detection are still open.

### Review
- Added recent temp-write tracking plus a synthetic `temp write followed by execve` behavior event in the eBPF sensor manager.
- Fixed the ringbuf exec path so temp-write→exec matching falls back to the tracked process `exe_path` when the raw eBPF exec event only carries a process name.
- Added process-name / executable-path mismatch weighting in the containment scorer.
- Verification: `cargo clippy --workspace -- -D warnings` passed.
- Verification: `cargo test --workspace` passed.

## Done: Workspace clippy hardening

### Scope
- [x] Run `cargo clippy --workspace -- -D warnings`
- [x] Fix every clippy warning without regressing behavior
- [x] Re-run clippy until it passes cleanly
- [x] Re-run relevant tests after the fixes

### Review
- Fixed the only workspace clippy failures in `server/src/feeds.rs` by switching stream error mapping to `std::io::Error::other`.
- Verification: `cargo clippy --workspace -- -D warnings` passed.
- Verification: `cargo test --workspace` passed.
- Note: Cargo reported a future-incompatibility notice for `sqlx-postgres v0.7.4`, but it does not fail clippy or tests today.

## Done: Container-aware detection follow-up from report review

### Scope
- [x] Extend tracked process metadata with container context and lightweight lineage hints
- [x] Use container context in the containment scorer to downgrade trusted containerized service temp activity
- [x] Add regression coverage for the `mariadbd`-inside-container style false-positive case
- [x] Re-review which report sections are still partial after the code change

### Notes
- Review correction: sections 15.5 and most of 15.6 were still missing; 15.2 and 15.4 were only partial.
- Goal: close the highest-priority gap called out in review without pretending Phase 2/3 work is complete.
- Remaining partial work after this patch: exec-chain/network correlation beyond temp-write→exec, persistence creation after temp staging, and miner-pattern detection are still not implemented.

## Done: Recreate follow-up tasks from `docs/05_Technical Investigation Report.md`

### Investigation-driven upgrade backlog
- [x] Recreate task inventory after manual cleanup of the old notes
- [x] Ship a concrete Detection v2 upgrade in the old containment scorer instead of leaving the report as documentation only
- [x] Reduce false positives for known benign temp-file activity described in the investigation report
- [x] Preserve genuinely suspicious temp-path behavior so the containment pipeline still escalates high-signal events
- [x] Add regression tests for the upgraded scorer behavior
- [x] Verify the agent crate still passes targeted tests after the scoring change

### Candidate follow-up tasks from the report
- [x] Package-manager awareness for `dpkg`/`apt` helper processes such as `depmod`, `cryptroot`, `update-initramfs`, and `ldconfig`
- [x] Known-runtime temp extraction downgrade for Java/OpenSearch/Solr JNI extraction patterns
- [x] Improve handling of `unknown process activity` so incomplete attribution is not treated as strong suspicion by itself
- [x] Add stronger malware-specific temp-path executable weighting
- [x] Add process-name / executable-path mismatch weighting for masquerade detection
- [ ] Evaluate future container-aware lineage enrichment beyond the current process snapshot model

### Current implementation target
- Upgrade the containment scorer to apply benign-context downgrades for package-maintenance helpers and known Java temp extraction patterns, and make `unknown process activity` require supporting suspicious signals before adding score.

### Review
- Implemented the upgrade in `agent/src/scorer.rs` rather than changing thresholds globally.
- Added temp-only benign-context downgrades for package-manager helpers and known Java/OpenSearch/Solr temp extraction behavior.
- Tightened `unknown process activity` so write-only unknown events no longer cross the suspicious threshold by bonus alone.
- Added a new high-signal boost for processes executing from `/tmp` or `/var/tmp`.
- Verification: `cargo test -p bannkenn-agent` passed after the change.
