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
