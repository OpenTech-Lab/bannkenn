# BannKenn Lessons Learned

## Session Log

### 2026-02-28 — MVP Implementation Start
- Project is self-hosted IPS (CrowdSec alternative) in Rust
- Two main components: agent (log watcher + firewall control) and server (REST API + DB)
- Strategy: Claude handles scaffolding + integration; Codex handles Rust implementation

## Patterns & Rules

### Docker: `COPY` has no shell fallback
- `COPY src dst 2>/dev/null || true` does NOT work — COPY is not a shell command and will fail if `src` is missing
- Fix: ensure the source path always exists (e.g., create `public/.gitkeep`) rather than trying to make the COPY conditional

### Docker slim images: use `wget` not `curl`
- `debian:bookworm-slim` does not include `curl` by default
- For healthchecks or lightweight HTTP calls in slim runtime images, install `wget` and use `wget -qO- <url>`
- `curl` requires an additional apt-get install and adds more image weight

### Axum: splitting a router into public + protected sub-routes
- Create two separate `Router` instances sharing the same `Arc<State>` via `with_state()`
- Apply `layer(auth_middleware)` only to the protected router
- Merge with `Router::merge()` before nesting — avoids duplicating state and keeps auth boundaries explicit

### Next.js standalone Docker output
- Set `output: 'standalone'` in `next.config.mjs` to produce a self-contained `server.js` entrypoint
- The runner stage only needs `node server.js` — no npm, no dev dependencies in the final image
- Copy three paths from builder: `public/`, `.next/standalone/`, `.next/static/`

### Public vs. auth for dashboard reads
- Self-hosted dashboards should not require users to manage bearer tokens in the browser
- Make GET (read) endpoints public; keep POST/DELETE (write) endpoints JWT-protected
- This is the correct tradeoff for a self-hosted single-operator tool

### Bash quoting in `sudo -u ... bash -lc` commands
- Avoid multiline double-quoted command strings for `bash -lc` when mixing `export` and build flags
- Prefer a single-quoted one-liner with explicit `;` separators to prevent tokenization surprises
- When interpolating local variables into a single-quoted remote command, splice only the needed variable segment (`'"$var"'`) and keep the rest single-quoted

### Installer completion checks must match promised actions
- If installer output tells users to run `systemctl start <service>`, the installer must have created and enabled that unit in the same execution path
- Add explicit verification for post-install claims (e.g., service unit presence) before considering installer changes done
- Keep runtime identity consistent: if the service runs as root (firewall operations), initialization instructions and config path must target root context

### Agent liveness must use explicit heartbeats
- Inferring agent health from decision traffic is incorrect because healthy agents may have no block events
- Track liveness with dedicated heartbeat writes from agent to server on a fixed interval
- Dashboard status should derive from heartbeat freshness windows, not decision table activity

### Sliding-window `Duration::from_secs(0)` silently breaks counting
- `Duration::from_secs(0)` = zero duration; `now.duration_since(oldest) > ZERO` is **always true** for any elapsed time
- Result: every existing entry is evicted before `push_back`, so the deque is perpetually length-1 → count never grows → no block event is ever generated
- Fix: enforce a minimum (e.g., `window_secs.max(10)`) and emit a `WARN` log when the configured value is suspiciously low
- Symptom: dashboard shows repeated `(1/N)` for the same IP with the count never advancing

### ButterflyShield seed must be window-aligned, not per-second
- Using `unix_sec` (changes every second) as the seed makes the effective threshold shift every second
- If the chaotic function produces a high multiplier in consecutive seconds, `attempts.len()` never catches `effective`; the block never fires
- Fix: quantize seed time to the window period — `unix_sec / window_secs.max(1)` — so all attempts within one window bucket share the same threshold
- Lesson: dynamic/chaotic thresholds must be stable across the detection window, not across arbitrary OS time units

### Burst path must clean up `ip_attempts` for the blocked IP
- When burst fires, the caller `return`s before reaching the `ip_attempts.push_back` step in the sliding-window path, BUT prior `ip_attempts` entries from earlier alerts are stale in the map
- Although `already_blocked` prevents reuse, failing to remove the stale VecDeque wastes memory proportionally to attack volume
- Fix: call `ip_attempts.remove(&raw.ip)` immediately after burst fires (alongside `burst_detector.clear_ip` and `already_blocked.insert`)

### Local block suppression must wait for firewall success
- Treating an IP as "already blocked" before `block_ip()` succeeds is incorrect; one failed firewall call can suppress every future retry for that attacker
- Keep duplicate block/listed events suppressed only while enforcement is in-flight, then clear the pending state on failure so the next hit retries immediately
- Do not clear per-IP attempt history until local enforcement succeeds, or the detector will restart from zero after a failed block attempt

### Container-exposed services need forward-path firewall rules
- Dropping only in host `INPUT` is insufficient for Docker or other forwarded traffic; published container ports usually traverse `FORWARD`
- BannKenn monitors Docker log files, so its firewall layer must cover both host traffic and forwarded/container traffic
- Fix: install block rules in both `INPUT` and `FORWARD` paths (or their nftables equivalents), and make rule/setup upgrades idempotent so existing installs pick up the new chain coverage

### Surge detectors need a cold-start bootstrap path
- A surge algorithm that waits a full baseline window before it can ever declare surge will miss the entire first sustained attack wave after process start
- If the system is expected to "level up" repeated same-category attacks quickly, add a bootstrap threshold for the no-baseline state instead of relying only on historical EMA comparisons
- Missing tests around cold-start behavior hide this class of bug; add explicit first-window regression coverage

### Runtime config defaults must reflect expected protection behavior
- If a feature like cross-IP campaign escalation is considered core detection behavior, leaving it absent/disabled in generated configs will look like an algorithm bug in production
- For backward compatibility, apply sane runtime defaults when optional config sections are missing, and make new configs persist those defaults explicitly
- If default thresholds are too conservative for real attacks, tune them based on user-observed behavior and add tests so the response profile stays intentional

### Central intelligence must be propagated, not just computed
- It is not enough for the server to collect telemetry and compute fleet-wide risk internally; agents must receive a consumable shared-risk snapshot if they are expected to tighten thresholds before final central block decisions are synced
- "Agent syncs block decisions" and "agent merges server-computed risk with local risk" are different capabilities and need separate end-to-end verification
- When both local and shared algorithms exist, compute them independently from the same base threshold and choose the more aggressive result explicitly instead of mixing intermediate state implicitly

### Offline-capable agents need cached state and a durable outbox
- Local scoring alone is not enough for disconnected operation; if the agent is expected to keep the "latest server picture", it must persist the last-known server-derived block knowledge and shared-risk snapshot to disk
- If risky-access reporting must survive server outages, failed uploads cannot just be logged and dropped; queue them durably and replay them when connectivity returns
- Verify offline behavior across both steady-state disconnects and restart-while-disconnected scenarios, because in-memory-only state hides restart regressions

### Public collection-like APIs must satisfy clippy shape expectations
- If a public type exposes `len()`, clippy expects a matching `is_empty()` for ergonomic and conventional API shape
- Run strict clippy on newly introduced public utility types before considering the task done, especially after adding small infrastructure modules like queues, caches, or wrappers

### GeoIP backfill validation must be agent-scoped
- After schema/backfill changes, verify specific affected agent rows (e.g., `/api/v1/agents/:id/decisions`) instead of only sampling global endpoints.
- If a user reports stale/null values, add a targeted backfill path and return post-update sample values from DB to confirm write success.

### Rustfmt CI must use pinned toolchain
- Floating `stable` in GitHub Actions can diverge from local rustfmt behavior and cause recurring `cargo fmt --check` failures.
- Pin a specific Rust toolchain version in workflow and mirror it with `rust-toolchain.toml`.
- After changing workflow/toolchain, always re-run `cargo fmt --all -- --check` locally to catch formatting differences before push.

### README operational steps must answer the exact user question explicitly
- If a command has important automatic follow-up behavior (for example, `update` auto-restarting a service), do not rely on a generic sentence alone.
- State the user-facing operational answer directly in README terms such as "you do not need to restart manually" so the expected next step is unambiguous.

### Updaters that restart services must verify steady-state health, not just restart command success
- A successful `systemctl restart` exit code does not prove the service stayed alive long enough to resume real work such as heartbeats.
- After self-updating a running service, verify post-restart liveness with a short `is-active` settle window and surface a status snapshot if the service dies immediately.

### Updaters must distinguish "already current" from a real upgrade
- Do not print "Updated X -> latest" when the installed version already matches the resolved latest release.
- Resolve the target release version before installation, skip the replace/restart path on a no-op, and print an explicit "already up to date" message instead.

### Reverse-proxy recommendations must not assume a domain exists
- If the user is operating on raw IPs or explicitly says they will not use a domain, do not default to hostname-based TLS examples.
- For single-IP deployments without host-based routing, prefer separate external TLS ports for each service and call out certificate trust requirements for IP/SAN or private CA setups.

### Optional compose services must be called out as opt-in
- If a feature is added behind a Compose profile, documentation must say plainly that `docker compose up -d` will not start it.
- When a user is expected to reach a TLS endpoint, include the exact profile-enabled startup command in the primary instructions instead of leaving it implicit.

### TLS examples must match the actual client connection address
- If a certificate is generated for one IP or hostname but clients connect through a different one, TLS will fail even if the server is otherwise healthy.
- For IP-based deployments, document that the certificate SAN must include every address clients will use, especially when both LAN and public IPs are involved.

### Self-signed TLS workflows need an explicit trust path for agents
- Saying "trust the certificate" is not enough operational guidance when the agent uses the OS trust store by default.
- If self-signed or private-CA TLS is part of the supported deployment path, provide either agent-level CA-file configuration or exact trust-store instructions in the primary docs.

### Release workflows must clean up partially-created releases on failure
- If a publish step can create a GitHub release before all assets are uploaded, a failing workflow can leave behind a broken release object that misleads users and breaks self-update paths.
- Prefer a draft-first publish flow with explicit cleanup on failure, and only mark the release public after the upload succeeds.

### API exposure and dashboard exposure must be treated separately
- Do not assume the dashboard needs the same public TLS posture as the agent-facing API; ask whether the dashboard is local-only before designing the deployment path.
- If the dashboard stays local, prefer a local-only plain HTTP path for it and optimize the secure/public path around the API instead of forcing both through the same TLS setup.

### Offline Docker Rust builds require a freshly regenerated vendor tree
- After adding or upgrading Rust dependencies in a repo that builds with `cargo --frozen` from `vendor/`, always regenerate the vendored crates before considering the change done.
- Do not stop at `cargo check` on the host; verify the offline path explicitly with a vendored `cargo build --frozen` and, when Docker is part of the product, the actual Docker build too.
- Prefer `cargo vendor --versioned-dirs` when multiple versions of the same crate exist, because mixed unversioned/versioned directory names can surface checksum collisions in Docker contexts.

### Interactive follow-up prompts must not reuse stdin behind an active lock
- If a setup flow locks `stdin` with `stdin.lock()` for earlier prompts and later calls another helper that reads from `stdin` directly, the second prompt can appear and then hang waiting behind the still-live lock.
- Before any follow-up registration/auth/TLS confirmation step that reads from stdin independently, explicitly drop the earlier locked reader or keep all prompts on the same reader abstraction.

### First-run security features should be configurable in `init`, not hidden behind manual file edits
- If an operator is expected to enable a feature like containment on a fresh host, `bannkenn-agent init` should offer that setup while the user is already answering prompts.
- For update flows, keep automation-safe defaults by making interactive reconfiguration explicit (for example `update --configure-containment`) instead of silently changing policy during every upgrade.

### Interval firewall sets must reconcile overlapping CIDRs and hosts as one effective block set
- If nftables uses an interval set, replaying raw decisions one-by-one is not order-independent: a host inside an existing CIDR, or a broader CIDR added after a host, will fail with `interval overlaps with an existing one`.
- Normalize and reconcile the full effective block pattern set first, remove superseded narrow entries before adding broader ones, and make watcher/listed checks understand CIDR coverage instead of exact-string matches only.

### Exact IP whitelists need firewall allow overrides when broader CIDRs remain blocked
- Removing only exact-match block entries is not enough when a whitelisted IP is still covered by an enforced CIDR such as `203.0.113.0/24`.
- Model whitelist enforcement as a first-class firewall allowlist with higher precedence than BannKenn drops, and reconcile that allowlist at startup, on sync, and when runtime events hit a whitelisted IP.

### Offline-delivery claims must verify the timestamp field end-to-end
- A durable outbox only proves eventual delivery; it does not prove the dashboard preserves original event time.
- For any claim about “correct timestamps” after offline buffering, trace the timestamp through event creation, outbox serialization, API payloads, DB insert code, and dashboard rendering before stating the behavior.

### Preserving event time also requires timeline queries to stop using insertion order
- Even after the original timestamp is stored correctly, a dashboard will still show outage-recovery bursts if its list queries sort by auto-increment `id` instead of event time.
- For buffered or replayed events, dashboard-facing “recent activity” queries should order by normalized event timestamp, with `id` only as a deterministic tie-breaker.

### TLS client errors need operator-facing translation for common deployment mismatches
- Raw rustls transport errors like `InvalidContentType` are not actionable enough for operators configuring agents against self-hosted servers.
- When an `https://` BannKenn agent URL hits a plain HTTP listener, classify that failure explicitly and tell the operator to either switch to `http://` or enable TLS on the server port.

### One-command deployment helpers should exist for the default path, not only the advanced TLS path
- If the repo provides a helper for native-TLS compose startup but leaves the normal HTTP dashboard/server path as manual `docker compose` plus environment trivia, operators will still hit avoidable setup mistakes.
- Shell helpers that start deployment stacks should explicitly set or clear the relevant env vars so stale TLS settings cannot leak across runs.

### Fresh-host TLS helpers should create missing certs or point to the real generator path
- A helper named like `dashboard-native-tls` should not stop at “missing certificate” on a clean host when the repo already includes a certificate generator.
- If documentation references a moved helper script path, fix the docs and wire the higher-level installer to the real generator so the primary setup flow stays self-contained.

### Systemd agent services must pin the same binary path and config home used by `sudo` operator flows
- If `connect`/`init` are usually run with `sudo`, the systemd unit must explicitly use root’s state home and should prefer the canonical installed binary path instead of whichever executable path happened to invoke the installer.
- Otherwise a manual `sudo bannkenn-agent connect` can appear successful while the service still runs a different binary or looks in a different home for `agent.toml` and pinned certs, leaving heartbeats offline.

### When follow-up gaps are identified, track them in `tasks/todo.md` before continuing implementation
- If a phase summary calls out concrete remaining gaps, add them as explicit tasks in `tasks/todo.md` before picking the work back up.
- Do not leave actionable follow-up only in prose or final-answer caveats; keep the repo task log aligned with the implementation queue.

### Deferred runtime-validation caveats belong in optional tasks, not only in handoff text
- If work is complete except for privileged/live-host validation, add that gap to the optional follow-up section in `tasks/todo.md`.
- That keeps future execution work discoverable and avoids losing an important validation step in reply text alone.

### Sensitive-data cleanup needs separate checks for the working tree and git history
- A repo can already have the live file sanitized while the sensitive value still exists in earlier commits.
- For requests to remove exposed IPs, tokens, or hostnames, verify both the current file contents and `git rev-list`/history matches before deciding whether to edit files, rewrite history, or both.

### When the user asks to scrub sensitive data, clean current files before discussing history rewrite
- Do not stop at explaining `git filter-repo` if the working tree still contains the exposed value in docs, tests, scripts, or task notes.
- First remove the live occurrences the user can still see in the repo, then handle history rewrite as a second step.

### Installer and setup scripts must take operator-specific network values from local config, not repo defaults
- Do not hard-code live IPs, hostnames, tokens, or deployment-specific paths into install/setup flows when a local `.env` or explicit CLI input is more appropriate.
- Provide a tracked `.env.example` with placeholders and keep the real `.env` local/ignored so operators can fill in their own values before running the scripts.
- When a script depends on operator-specific values, document the `.env` step in the primary setup instructions instead of burying it in flags alone.

### README quick starts should stay `.env`-first and avoid flag-heavy happy paths
- When the normal workflow is "fill in `.env`, then run a script", make that the primary README path instead of leading with long one-off flag examples.
- Keep advanced flags like `--tls-san` in optional troubleshooting or advanced sections, not in the default setup flow.
- For this repo, prefer documenting `scripts/install.sh` and `scripts/update-server.sh` as the main operator entrypoints.

### Top-level `How to use` sections should stay short
- If the user asks for a quick usage section, keep it as a compact operator checklist rather than repeating the full README.
- For this repo, the top-level `How to use` section should stay under 100 lines and focus on `.env`, `scripts/install.sh`, and `scripts/update-server.sh`.

### Do not mark report recommendations complete when the implementation only covers part of the capability
- If a report item depends on missing runtime metadata such as container lineage, exec-chain context, or masquerade checks, keep the task explicitly partial until that metadata exists in code.
- Before closing a recommendation as "done", map each sub-capability in the report to the exact code path and test that proves it.
- Prefer leaving a smaller set of completed checkboxes and a sharper backlog over overstating coverage in `tasks/todo.md` or handoff text.

### Malware-trigger recommendations need per-signal tracking, not one umbrella checkbox
- For sections like "stronger malware-specific triggers", do not collapse several distinct detections into one completed task just because one signal landed.
- Track temp-write→exec, path/name mismatch, persistence, network follow-on, and miner-pattern triggers separately unless the code truly implements all of them.
- If one setup mode is preferred, say that directly in the quick-start instead of making users infer it.

### Before starting the next phase, do the maintainability pass while the context is still fresh
- If a large phase adds oversized files or growing inline tests, refactor them before starting the next phase instead of treating cleanup as optional follow-up.
- Keep server tests in `server/tests/` with shared fixtures/modules rather than expanding `#[cfg(test)]` blocks inside production files.
- Prefer thin binaries and domain-focused modules so the next upgrade extends existing seams instead of reopening monolith files.

### Relocating Rust tests under `tests/` needs a real Cargo entrypoint, not only source-file `#[path]` hooks
- Moving test bodies out of `src/` is only half the refactor; Cargo discovers integration tests from top-level files like `tests/unit.rs`, not from nested directories alone.
- When externalizing a large Rust test tree, add the manifest test file in the same change and verify `cargo test --test <name>` runs it directly before calling the relocation complete.
- If the goal is "tests live under `tests/`", prove the new files are wired as a discovered test binary instead of assuming `#[cfg(test)] #[path = ...] mod tests;` inside production modules is sufficient.

### Formatting-only CI gates still need explicit `cargo fmt --all -- --check` verification
- Do not assume `cargo fmt --all` touched every relocated test file correctly just because code compiled and clippy passed.
- After moving or generating Rust test files, run `cargo fmt --all -- --check` explicitly and fix any remaining diffs before closing the task.
- Treat formatter verification as separate from test and clippy verification in `tasks/todo.md`.

### Runtime classifiers and ID parsers must evolve together
- If one parser recognizes a platform-specific marker like `crio-<id>`, audit the paired metadata inference path so it emits the matching runtime label as well.
- For container context in this repo, keep `container_runtime` and `container_id` extraction aligned across Docker, containerd, Podman, CRI-O, and Kubernetes cgroup variants.
- Add a regression test for the exact cgroup shape reported in review whenever a new runtime prefix is supported.

### Overlapping score suppressors must aggregate by component, not by reason bucket
- If multiple benign contexts suppress the same rename/write/delete/throughput burst, compute suppression once per component and then attach all matching reasons.
- Do not let independent "known benign" branches each subtract the full component set, or one process can be downgraded more than intended just because contexts overlap.
- Add a regression test for at least one realistic overlap case whenever a new benign-context suppressor is introduced.

### Short classifier markers need exact command-name matching, not substring scans
- Markers like `sh`, `apt`, and `rpm` are too short for raw `contains()` checks across full process names or command lines; they will match unrelated names like `containerd-shim` or `capturer`.
- For scorer-side helper/process/shell classification in this repo, compare normalized basenames and `argv[0]` command names exactly, and use a separate narrower matcher when runtime metadata needs token/segment matching.
- Add regressions for at least one false-positive substring case whenever a new short marker is introduced.

### CI lint fixes need full workspace verification, not only the first reported warning
- When GitHub Actions fails on an initial clippy warning, do not stop after patching the first printed lines; rerun `cargo clippy --workspace -- -D warnings` locally until the workspace is clean because later lints may be hidden behind the first failure.
- Prefer structural fixes over `#[allow(...)]`: replace long tuple spellings with type aliases and replace long helper argument lists with typed request structs so the code gets simpler while satisfying the lint.

### Cross-target Rust builds must isolate Linux-only crates and impls at both Cargo and source level
- If the project ships a Windows target, do not add Linux-only crates like `aya` as unconditional dependencies; move them into `[target.'cfg(target_os = "linux")'.dependencies]` or a Linux-only feature boundary.
- Mirror that split in source: gate Linux-only imports, trait impls, structs, and helper functions with `#[cfg(target_os = "linux")]`, and provide a clean non-Linux fallback path instead of relying on runtime `unreachable!()`.
- When the local machine lacks the foreign stdlib, verify the target split with `cargo tree --target ...` in addition to native `cargo check`/`clippy` so target-specific dependency leaks are still caught before CI.

### Self-update must target the managed service binary, not just the currently running executable
- If a systemd unit prefers `/usr/local/bin/bannkenn-agent`, `sudo bannkenn-agent update` must resolve and replace that managed path even when the invoking shell found a different copy on `PATH`.
- Refresh the systemd unit during self-update before restart so the background service stays pinned to the same binary/config path used by `init` and `connect`; otherwise manual diagnostics can succeed while heartbeats from the service stay offline.

### Resource-install answers must state the scope first
- When an operator asks whether a support file like `bannkenn-containment.bpf.o` belongs "on the server", answer the deployment scope first: it is needed only on hosts that run `bannkenn-agent`, not on server/dashboard-only machines.
- Give the exact installed paths in the same answer so the operator can verify quickly without inferring where the file should live.

### Optional packaging paths must match the user's real deployment model
- Do not assume an optional Docker packaging path is valuable when the actual operator workflow is "download GitHub Release assets, then run `sudo bannkenn-agent init` on the host."
- If a TODO mentions an optional packaging path, call out clearly that it is optional and confirm whether the user wants it kept before treating it as part of the preferred deployment story.

### Mixed lib/bin crates should keep CLI-only modules out of `lib.rs`
- In a package that builds both a library and a binary from the same `src/` tree, exporting a CLI-only module from `lib.rs` creates a second compiled copy that can trip `dead_code` even when the binary uses it.
- If a module is only used by `main.rs` command paths, keep it behind `mod ...;` in the binary and do not re-export it from the library unless another crate or library code truly needs it.

### No-op self-updates must still repair required sidecar assets
- If a release ships a managed sidecar asset such as `bannkenn-containment.bpf.o`, `bannkenn-agent update` should not stop at "already up to date" before checking whether that asset is missing.
- A same-version update should be able to self-heal the sidecar asset and restart the running service only when the repair actually changed on-disk state.

### Verifier-backed eBPF load failures need full error-chain logging
- Wrapping Aya `ProgramError::LoadError` in `anyhow` context and then logging it with plain `{}` can hide the kernel verifier output, leaving only a useless top-level line like `failed to load bk_file_openat`.
- For startup fallback paths, log the full chain with `{:#}` and enable verbose verifier logs in `EbpfLoader` so operators can diagnose rejected programs directly from `journalctl`.

### Mutation response contracts must be explicit about empty bodies
- If a dashboard helper treats a successful mutation as JSON, the server route must return JSON consistently or the client must explicitly handle `204 No Content`; do not leave that contract implicit.
- For rename/edit flows where the UI immediately needs the refreshed display label, prefer returning the updated resource from the mutation route and keep a client-side empty-body fallback for older servers.
- When a nickname augments a stable original agent name, use one shared formatter for tables, dialogs, links, and toast text so the `nickname(original-name)` presentation stays consistent.

### Bot-config fixes should follow the tool's schema exactly
- For `.coderabbit.yaml`, do not invent flat booleans like `reviews.enable_review`; use the documented nested key path such as `auto_review.enabled`.
- When a review bot reports a schema error, fix the exact key structure first instead of assuming the value is the problem.
