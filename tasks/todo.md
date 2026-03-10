# BannKenn MVP Task List

## Phase 1 – Scaffolding (Claude)
- [x] Create tasks/todo.md
- [x] Create tasks/lessons.md
- [x] Create workspace Cargo.toml
- [x] Create .gitignore
- [x] Create docker/docker-compose.yml
- [x] Create docker/Dockerfile.server
- [x] Create scripts/install.sh
- [x] Create .github/workflows/ci.yml

## Phase 2 – Rust Implementation (Codex workers, parallel)
- [x] Rust Agent (agent/src/) — Codex Worker A
  - [x] main.rs — CLI entry (clap)
  - [x] config.rs — Config loading
  - [x] watcher.rs — Log tail + pattern detection
  - [x] firewall.rs — nftables/iptables blocking
  - [x] client.rs — HTTP client → server
  - [x] agent/Cargo.toml
- [x] Rust Server (server/src/) — Codex Worker B
  - [x] main.rs — Axum server startup
  - [x] config.rs — Config loading
  - [x] db.rs — SQLite schema + queries
  - [x] routes/mod.rs
  - [x] routes/decisions.rs
  - [x] routes/agents.rs
  - [x] routes/health.rs
  - [x] auth.rs — JWT middleware
  - [x] feeds.rs — Community feed ingestion
  - [x] server/Cargo.toml

## Phase 3 – Integration & Verification (Claude)
- [x] cargo check --workspace passes (0 errors, warnings only)
- [x] cargo test --workspace passes (23/23 tests pass)
- [x] docker compose up -d — server starts
- [x] curl localhost:3022/api/v1/health → {"status":"ok"}
- [x] Agent init command runs without panic

## Review
- Phase 3 fixes applied by Claude:
  - `auth.rs`: Added `#[async_trait]` to `FromRequestParts` impl (axum-core 0.4.5 requires it)
  - `routes/agents.rs`: Block-scoped `ThreadRng` usage to drop before `.await` (ThreadRng is !Send)
  - `main.rs`: Added `std::net::SocketAddr` type annotation to `config.bind.parse()`
  - Cleaned up unused imports in `config.rs`, `db.rs`, `routes/decisions.rs`
  - `db.rs`: Switched to `SqliteConnectOptions::create_if_missing(true)` — bare `connect()` won't create file
  - `docker/Dockerfile.server`: Bumped to `rust:slim-bookworm` (latest ≥ 1.88) — `time@0.3.47` requires rustc 1.88

## Phase 4 – Dashboard (Claude)
- [x] Next.js 15.3 app in `dashboard/` — TypeScript, Tailwind, App Router
- [x] `dashboard/app/page.tsx` — stat cards + decisions table, 10s polling
- [x] `dashboard/app/api/decisions/route.ts` — proxy to `GET /api/v1/decisions`
- [x] `dashboard/app/api/health/route.ts` — proxy to `/api/v1/health`
- [x] `dashboard/next.config.mjs` — `output: 'standalone'` for Docker
- [x] `docker/Dockerfile.dashboard` — Node 22 Alpine multi-stage build
- [x] `docker/docker-compose.yml` — added dashboard service on port 3021
- [x] Server `GET /api/v1/decisions` made public (no JWT) for dashboard reads
- [x] Server `Dockerfile.server` — added `wget` to runtime stage for healthcheck
- [x] Verified: both containers healthy, 77k+ blocked IPs visible in API

## Review (Phase 4)
- Fixes applied:
  - `dashboard/public/.gitkeep` added — Docker COPY requires source path to exist; `|| true` doesn't work in Dockerfile
  - `next` bumped 15.1.0 → 15.3.0 for CVE-2025-66478
  - Server healthcheck changed from `curl -f` to `wget -qO-` — curl not in `debian:bookworm-slim`
- Final state: `curl localhost:3022/api/v1/health` → `{"status":"ok"}` | `curl localhost:3021/api/health` → `{"status":"ok"}`

## Phase 5 – Installer Cargo PATH Fix (Codex)
- [x] Reproduce installer failure context (`sudo -u` cannot find cargo for invoking user)
- [x] Patch `scripts/install.sh` to resolve cargo in login shell + `~/.cargo/bin` fallback
- [x] Verify installer script syntax and cargo detection command path

## Review (Phase 5)
- `scripts/install.sh` updated to use `sudo -iu "$build_user" bash -lc ...` for both cargo detection and build
- Added `export PATH="$HOME/.cargo/bin:$PATH"` in both execution paths to ensure rustup-installed cargo is discoverable
- Verified syntax with `bash -n scripts/install.sh`
- Verified detection path in target context: `sudo -iu toyofumi ... command -v cargo` → `/home/toyofumi/.cargo/bin/cargo`
- Fixed quoting bug in build invocation that caused `export: --release not a valid identifier`
- Verified full fixed build command succeeds in sudo user context:
  `sudo -iu toyofumi bash -lc 'export PATH="$HOME/.cargo/bin:$PATH"; cargo build --release --manifest-path "/home/toyofumi/Project/bannkenn/Cargo.toml" --bin bannkenn-agent'`

## Phase 6 – Installer systemd unit creation fix (Codex)
- [x] Identify why `systemctl status bannkenn-agent` reports unit not found after install
- [x] Patch installer to create/enable `bannkenn-agent.service` during install
- [x] Align post-install instructions with service runtime context (`sudo bannkenn-agent init`)
- [x] Verify installer script syntax

## Review (Phase 6)
- Root cause: `configure_systemd()` existed but was never invoked in `main()`
- Added `configure_systemd` invocation before completion message
- Updated config directory target to `/root/.config/bannkenn` to match root-run service
- Updated post-install guidance to:
  - `sudo bannkenn-agent init`
  - `sudo systemctl start bannkenn-agent`

## Phase 7 – Dashboard agent status + community IP page (Codex)
- [x] Add server API to list agents with derived health/status
- [x] Track decision source by authenticated agent name for future status accuracy
- [x] Add dashboard API proxy for agents endpoint
- [x] Update dashboard home page to show agent health/status
- [x] Add new dashboard page to display community IP list entries
- [x] Verify with `cargo check --workspace`; attempted `npm run lint` in dashboard (blocked: `next` not installed)

## Review (Phase 7)
- Added `GET /api/v1/agents` with derived status (`online` if last decision seen within 5 minutes; otherwise `offline`/`unknown`)
- Added `GET /api/v1/community/ips` for community-feed-backed IP list aggregation
- `POST /api/v1/decisions` now records `source` as authenticated agent name to make per-agent status meaningful
- Dashboard home now fetches `/api/agents` and renders an `Agent Status` table + agent health stats
- Added dashboard page `/community` that lists community IPs with source, sightings, and last seen
- Added top navigation links in dashboard layout (`Home`, `Community IPs`)
- Verification:
  - `cargo check --workspace` passed
  - `cargo check -p bannkenn-server` passed
  - `npm run lint` failed in this environment because `next` binary is unavailable (dependencies not installed)

## Phase 8 – Agent heartbeat for accurate status (Codex)
- [x] Add server heartbeat storage + query plumbing
- [x] Add authenticated heartbeat endpoint for agents
- [x] Update agent status computation to use heartbeat timestamp
- [x] Add periodic heartbeat sender in agent runtime
- [x] Verify with `cargo check --workspace`

## Review (Phase 8)
- Added `agent_heartbeats` table migration and `upsert_agent_heartbeat(agent_name)` in DB layer
- Added protected `POST /api/v1/agents/heartbeat` endpoint (JWT required; agent identity from token subject)
- `GET /api/v1/agents` status now derives from heartbeat timestamp, not decision activity
- Online threshold tightened to 2 minutes for heartbeat freshness
- Agent runtime now sends heartbeat immediately on startup and every 30 seconds afterward
- Verification: `cargo check --workspace` passes (existing unrelated warning in `agent/src/watcher.rs`)

## Phase 9 – Auto token setup in agent init (Codex)
- [x] Update `bannkenn-agent init` to auto-register agent and fetch JWT after server URL entry
- [x] Keep manual JWT entry as fallback when auto-registration fails
- [x] Update default server URL prompt to current server port
- [x] Verify with `cargo check -p bannkenn-agent`

## Review (Phase 9)
- `bannkenn-agent init` now prompts for agent name and can auto-fetch JWT via `POST /api/v1/agents/register`
- Added robust fallback: if auto-registration fails (or user says no), prompt for manual JWT token input
- Default server URL updated from `http://localhost:8080` to `http://localhost:3022`
- Added helper functions in agent init flow:
  - `register_agent_and_get_token(server_url, agent_name)`
  - `prompt_for_jwt_token(...)`
- Verification: `cargo check -p bannkenn-agent` passes (existing unrelated warning in `watcher.rs`)

## Phase 10 – Home recent decisions filter to blocked IPs only (Codex)
- [x] Update home page Recent Decisions table to show only `action=block`
- [x] De-duplicate by IP to show newest blocked IP entries
- [x] Update empty-state copy for blocked-only table

## Review (Phase 10)
- `dashboard/app/page.tsx` now computes `recentBlockedByIp` from decisions:
  - filters to block actions only
  - keeps first (newest) entry per IP
- Recent Decisions table now renders `recentBlockedByIp` instead of all decisions
- Empty state text changed to `No blocked IPs yet`

## Phase 11 – Exclude community feed items from home Recent Decisions (Codex)
- [x] Filter out community feed sources in home blocked list

## Review (Phase 11)
- Home `Recent Decisions` now excludes entries where `source` ends with `_feed` (e.g. `ipsum_feed`)

## Phase 12 – Exclude community feed from home stats (Codex)
- [x] Update `Total decisions` to count non-feed decisions only
- [x] Update `Blocked IPs` to count non-feed block decisions only

## Review (Phase 12)
- Home stats now use `localDecisions` (source not ending with `_feed`) for both total and blocked counters

## Phase 13 – Agent init auto-detect log sources (Codex)
- [x] Remove manual log path prompt from `bannkenn-agent init`
- [x] Auto-discover host/docker/k8s/vm-mounted log candidates and print as a numbered list
- [x] Auto-select a log path deterministically for `agent.toml` without user input
- [x] Verify with `cargo check -p bannkenn-agent`

## Review (Phase 13)
- `agent/src/main.rs` `init()` no longer prompts for `Log file path`; it now runs automatic source discovery.
- Added host log detection (`/var/log/auth.log`, `/var/log/secure`, `/var/log/syslog`, `/var/log/messages`).
- Added container log discovery for Docker (`/var/lib/docker/containers/*/*-json.log`) and Kubernetes-style paths (`/var/log/containers`, `/var/log/pods`).
- Added best-effort VM/external mount scanning from `/mnt`, `/media`, `/run/media`, and `/vmfs/volumes` for common auth/system log names when readable.
- `init()` now prints discovered logs as a numbered list and auto-selects a primary path via explicit priority order.
- Verification: `cargo check -p bannkenn-agent` passes (existing unrelated warning in `agent/src/watcher.rs` about unused `timestamp` field).

## Phase 14 – ButterflyShield Dynamic Detection Mode (Codex)
- [x] Define a `butterfly_shield` config flag and parameters (seed source, base threshold multiplier bounds)
- [x] Implement chaos-based dynamic threshold helper in agent detection path
- [x] Apply dynamic thresholding to failed-attempt scoring without breaking existing static behavior
- [x] Add server/dashboard visibility for dynamic mode status and effective threshold values
- [x] Add tests for deterministic behavior under fixed seed and bounds safety
- [x] Verify with `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`

## Review (Phase 14)
- Created `agent/src/butterfly.rs`: logistic-map chaos function (`r=3.99`, 10 iterations), `effective_threshold(base, ip, cfg)` with IP+timestamp seed via `DefaultHasher`, multiplier clamped to `[0.5, 1.5]` range. 5 unit tests (bounds, determinism, minimum threshold, sensitivity, disabled fallback).
- Updated `agent/src/config.rs`: added `pub butterfly_shield: Option<ButterflyShieldConfig>` with `#[serde(default)]`. Updated `Default` impl.
- Updated `agent/src/lib.rs`: added `pub mod butterfly;`.
- Updated `agent/src/watcher.rs`: replaced static threshold check with dynamic chaos-based logic when `butterfly_shield.enabled = true`; reason string includes effective threshold value.
- Updated `server/src/db.rs`: idempotent `ALTER TABLE agent_heartbeats ADD COLUMN butterfly_shield_enabled INTEGER` migration; `list_agents_with_last_seen` returns 7-tuple with `Option<i64>` mapped to `Option<bool>`; `upsert_agent_heartbeat` stores the flag.
- Updated `server/src/routes/agents.rs`: `AgentStatusResponse` includes `butterfly_shield_enabled: Option<bool>`; `heartbeat()` accepts `Option<Json<HeartbeatRequest>>` and forwards flag to DB.
- Updated `agent/src/client.rs`: `send_heartbeat` accepts and sends `butterfly_shield_enabled: Option<bool>` in JSON body.
- Updated `agent/src/main.rs`: added `mod butterfly;`; `init()` sets `butterfly_shield: None`; heartbeat loop captures and forwards butterfly config state.
- Updated `dashboard/app/page.tsx`: added `butterfly_shield_enabled?: boolean | null` to `AgentStatus` interface; added "ButterflyShield" column with purple "Active" badge / "Inactive" / "—" rendering.
- Verification: `cargo fmt --all` clean, `cargo clippy --workspace --all-targets -- -D warnings` 0 warnings, `cargo test --workspace` 97/97 tests pass.

## Phase 15 – Agent detail dashboard page (Codex)
- [x] Add server endpoint to fetch decisions for a specific agent
- [x] Add dashboard API proxy for per-agent decisions
- [x] Add dashboard API proxy for IP geolocation/organization lookup (best-effort fallback)
- [x] Link agent rows on home page to agent detail page
- [x] Build `/agents/[id]` detail page with:
  - [x] scanned vs risky summary cards
  - [x] bar/line visualizers for request reasons, top IPs, and recent trend/forecast
  - [x] detailed table with IP, reason, country, organization, timestamp
- [x] Verify with `cargo check -p bannkenn-server` and `npm run build` in `dashboard/`

## Review (Phase 15)
- Server:
  - Added `GET /api/v1/agents/:id/decisions?limit=...` to return decisions for one agent source.
  - Added DB helpers `get_agent_name_by_id` and `list_decisions_by_source`.
- Dashboard:
  - Home page agent names now link to `/agents/:id`.
  - Added proxy route `GET /api/agents/:id/decisions`.
  - Added proxy route `GET /api/ip-intel?ip=...` using `ipwho.is` with timeout + in-memory cache + graceful fallback.
  - Added `/agents/[id]` detail page with:
    - Detected/scanned and real-risky(blocked) metrics
    - Top reason and top IP bar charts
    - 24h trend chart and next-hour forecast bar
    - Event table with IP, reason, action, country, organization, timestamp
- Verification:
  - `cargo check -p bannkenn-server` passed
  - `npm run build` in `dashboard/` passed (includes new dynamic route)

## Phase 18 – SSH repeated connection close not escalating to block (Codex)
- [x] Reproduce and identify why `SSH repeated connection close (2/3)` stays alert-only
- [x] Implement escalation fix so strong SSH auth-failure-close signals block immediately
- [x] Add/extend tests for new SSH escalation behavior
- [x] Verify with `cargo test -p bannkenn-agent`

## Review (Phase 18)
- Root cause: `SSH repeated connection close` was treated as a normal sliding-window signal, so sparse scanner traffic often hovered at `2/3` and kept generating alert telemetry without reaching block.
- Fix: added immediate-block classification for high-confidence SSH auth-failure-close reasons:
  - `SSH repeated connection close`
  - `SSH disconnected: too many auth failures`
  - `SSH max auth attempts exceeded`
- Implementation: `agent/src/watcher.rs`
  - Added `is_immediate_block_signal(reason)` helper.
  - In detection flow, after computing effective threshold, immediate-block reasons now emit `level=block`, trigger firewall path, and clear per-IP attempt state.
- Added unit tests in `watcher.rs` for positive/negative reason matching.
- Verification: `cargo test -p bannkenn-agent` passed (58/58 in lib and 58/58 in bin).

## Phase 16 – MMDB-based GeoIP/ASN enrichment + DB backfill (Codex)
- [x] Add server-side GeoIP resolver using local MMDB files (`GeoLite2-Country.mmdb`, `GeoLite2-ASN.mmdb`)
- [x] Extend `decisions` schema with `country` and `asn_org` columns (idempotent migration)
- [x] Enrich new decisions at insert time from MMDB with `Unknown` fallback
- [x] Add startup backfill to populate existing rows where values are null/empty/Unknown
- [x] Update detail page to use DB-provided `country` and `asn_org`
- [x] Ensure Docker runtime includes MMDB files and sets `BANNKENN_MMDB_DIR`
- [x] Rebuild/restart server container to execute backfill against live `/data/bannkenn.db`

## Review (Phase 16)
- Added `server/src/geoip.rs` with lazy-loaded MMDB readers and `lookup(ip)` helper.
- `server/src/db.rs` now stores `country` + `asn_org` in `DecisionRow`, migrates columns, enriches writes, and includes `backfill_decision_geoip_unknowns()`.
- `server/src/main.rs` runs backfill on startup and logs updated row count.
- `dashboard/app/agents/[id]/page.tsx` now reads country/ASN org directly from decision rows.
- Docker updates:
  - `docker/Dockerfile.server` copies `server/data` into runtime image.
  - `docker/docker-compose.yml` sets `BANNKENN_MMDB_DIR=/app/server/data`.
- Runtime follow-up:
  - Changed backfill to run in background (non-blocking startup) and enabled SQLite `WAL` + `busy_timeout(30s)` to avoid lock contention with feed ingestion.
  - Rebuilt/restarted `bannkenn-server`; container is healthy and API decisions now include `country` and `asn_org`.

## Phase 17 – Full telemetry pipeline + multi-log monitoring (Codex)
- [x] Add server telemetry table + idempotent migration (`telemetry_events`)
- [x] Add protected telemetry ingest endpoint for agents (`POST /api/v1/telemetry`)
- [x] Add server query endpoints for per-agent telemetry (`GET /api/v1/agents/:id/telemetry`)
- [x] Update agent watcher to emit telemetry events for every match (`alert` and `block`)
- [x] Update agent runtime to send telemetry events and keep block decision flow for blocks
- [x] Add multi-log-path support in agent config + watcher (host/docker/k8s concurrently)
- [x] Update dashboard agent detail page counters/charts/table to use telemetry events
- [x] Verify with `cargo check --workspace` and `npm run build` in `dashboard/`

## Review (Phase 17)
- Server:
  - Added `telemetry_events` table with source/log_path/geo columns and index on `(source, created_at)`.
  - Added protected telemetry ingest endpoint `POST /api/v1/telemetry` (agent identity from JWT subject).
  - Added per-agent telemetry endpoint `GET /api/v1/agents/:id/telemetry`.
- Agent:
  - Replaced block-only watcher flow with `SecurityEvent` pipeline that emits telemetry for every matched detection:
    - `level=alert` before threshold
    - `level=block` when threshold reached
  - Runtime now sends telemetry for every event and only executes firewall + decision report on `block`.
  - Added multi-log monitoring via `log_paths` (backward-compatible with existing single `log_path`).
- Dashboard:
  - Added API proxy `GET /api/agents/:id/telemetry`.
  - Agent detail page now uses telemetry events for scanned/risky counters, charts, and event table.
- Verification:
  - `cargo check --workspace` passed
  - `npm run build` in `dashboard/` passed

## Phase 19 – Retry local enforcement when same IP keeps attacking (Codex)
- [x] Confirm root cause for repeated same-IP attacks not resulting in durable local blocks
- [x] Refactor agent suppression state so failed firewall enforcement does not silence future retries
- [x] Add regression tests for failed local block attempts and subsequent reprocessing
- [x] Verify with targeted and full agent test runs

## Review (Phase 19)
- Root causes identified:
  - The watcher marked an IP as effectively blocked before `block_ip()` succeeded, so one failed local firewall call could silence future retries for the same attacker.
  - The firewall only dropped traffic in `INPUT`, which does not cover forwarded/container-published traffic; Docker-hosted services could keep receiving requests even after a “successful” block.
- Fixes:
  - Added watcher/main feedback flow so duplicate block events are suppressed only while a local block is in-flight, then retried if enforcement fails.
  - Preserved per-IP attempt history across failed local block attempts, so the next hit re-triggers blocking immediately instead of restarting the counter from 0.
  - Added a separate `enforced_blocked_ips` cache so only successfully enforced local blocks are treated as suppressed.
  - Extended firewall coverage to both host `INPUT` traffic and forwarded/container traffic (`FORWARD` for iptables, `forward` chain for nftables).
  - Made nftables element insertion idempotent when an IP is already present.
- Verification:
  - `cargo fmt --all`
  - `cargo check -p bannkenn-agent`
  - `cargo test -p bannkenn-agent`
  - `cargo check --workspace`

## Phase 20 – Cross-IP risky category escalation fix (Codex)
- [x] Confirm why repeated risky categories across different IPs stay at static rank tags like `Invalid SSH user [High]`
- [x] Patch first-window surge logic so repeated same-category attacks can escalate without waiting an entire baseline window
- [x] Ensure runtime configs that omit cross-IP campaign settings still enable category escalation with sane defaults
- [x] Add regression tests and verify with agent/workspace checks

## Review (Phase 20)
- Root causes identified:
  - The surge detector had a cold-start blind spot: it would not enter `surge` mode until after a full baseline window elapsed, so the first sustained wave of the same risky category stayed stuck at static rank tags.
  - Cross-IP campaign escalation was optional and omitted by default in generated/legacy configs, so repeated `Invalid SSH user` events from different IPs often never escalated beyond `[High]`.
- Fixes:
  - Added bootstrap surge logic so a fresh same-category wave can escalate within the first active surge window instead of waiting an entire window to learn a baseline.
  - Enabled runtime default campaign detection when the config omits a `campaign` section, and made `init` persist that default explicitly for new agents.
  - Tightened the default volume campaign threshold from 5 distinct IPs to 3 distinct IPs for faster category-level escalation.
- Added regression coverage for:
  - bootstrap surge activation in `event_risk`
  - threshold reduction on bootstrap surge
  - runtime default campaign config population
- Verification:
  - `cargo test -p bannkenn-agent event_risk -- --nocapture`
  - `cargo test -p bannkenn-agent campaign -- --nocapture`
  - `cargo test -p bannkenn-agent config -- --nocapture`
  - `cargo test -p bannkenn-agent`
  - `cargo check --workspace`
  - `cargo fmt --all -- --check`

## Phase 21 – Shared server risk propagation to agents (Codex)
- [x] Verify current implementation against the end-to-end risk-sharing spec
- [x] Add server-side shared risk profile calculation from fleet telemetry
- [x] Add protected agent API to fetch shared risk profile periodically
- [x] Merge shared server risk with local agent risk and choose the more aggressive block threshold
- [x] Add regression tests and verify server/agent/workspace behavior

## Review (Phase 21)
- Findings against the requested behavior:
  - Agent block sync already existed and remained correct.
  - Risk telemetry upload already existed, but the server did not share any computed global risk profile back to agents.
  - Agent-side blocking only used local environment signals plus delayed server block decisions; it did not merge local risk with server-computed fleet risk before blocking.
- Implemented:
  - Server-side shared fleet risk profile computation from recent telemetry, including:
    - global risk pressure multiplier
    - per-category shared surge/campaign overrides
  - Protected agent endpoint `GET /api/v1/agents/shared-risk`
  - Periodic agent fetch of shared risk alongside normal sync
  - Agent-side merge that computes local and shared thresholds independently and uses the more aggressive one
  - Shared reason tags (`shared:global`, `shared:surge`, `shared:campaign`) so the chosen server-side contribution is visible in telemetry/decisions
- Behavior after this phase:
  - Agent still blocks immediately on strong local signals
  - Agent still syncs server block decisions periodically
  - Server now shares fleet-wide risk to agents, so agents can preemptively tighten thresholds before a final central block decision arrives
  - Final block threshold is now the minimum of local effective threshold and shared server effective threshold
- Verification:
  - `cargo fmt --all`
  - `cargo fmt --all -- --check`
  - `cargo test --workspace`
  - `cargo check --workspace`

## Phase 22 – Offline agent continuity with cached server state (Codex)
- [x] Verify current disconnect behavior for server-derived state and outbound reporting
- [x] Persist last-known shared risk and block knowledge locally for offline startup/use
- [x] Add a durable local outbox for telemetry/decision/login reports and periodic retry
- [x] Verify agent behavior with focused tests and workspace checks

## Review (Phase 22)
- Findings against the requested behavior:
  - Local blocking and local risk scoring already continued working without the server, including host/machine risk and threat-type risk adjustments.
  - The last server picture was only kept in memory, so an agent restart during a server outage lost shared-risk state and known server block knowledge.
  - Failed telemetry/decision/login uploads were only logged and dropped; they were not retained for later replay when connectivity returned.
- Implemented:
  - Added persistent offline cache for last-known blocked IP knowledge plus the latest shared-risk snapshot.
  - Agent startup now restores cached blocked IPs into the local firewall before any network call, then refreshes from the server when reachable.
  - Added a durable local outbox for telemetry, decisions, and SSH-login reports, with periodic retry and immediate wake-up on new events.
  - Local block events now persist into the offline block cache so offline-created blocks survive agent restart even before the server acknowledges them.
- Behavior after this phase:
  - If the server is reachable, the agent still refreshes block decisions and shared fleet risk normally.
  - If the server is unreachable, the agent continues using the last cached server state and keeps updating local host risk, threat-type risk, surge, campaign, and block logic in real time.
  - Events generated while disconnected are retained locally and flushed later instead of being lost.
- Verification:
  - `cargo fmt --all`
  - `cargo test -p bannkenn-agent`
  - `cargo check --workspace`

## Phase 23 – Release script default patch bump (Codex)
- [x] Inspect current release script version resolution
- [x] Add no-argument behavior that auto-increments the current patch version
- [x] Verify the script syntax and no-argument resolution path safely

## Review (Phase 23)
- Implemented:
  - Updated `scripts/release.sh` so `./scripts/release.sh` now bumps the current workspace patch version automatically.
  - Kept explicit version usage unchanged, so `./scripts/release.sh 1.4.0` still releases exactly the requested version.
  - Added a guard that only auto-increments plain release versions (`x.y.z`); prerelease/current nonstandard versions still require an explicit target.
- Verification:
  - `bash -n scripts/release.sh`
  - `bash scripts/release.sh` in the current dirty worktree, confirming `1.3.16 → 1.3.17` before the existing clean-tree pre-flight guard stopped execution

## Phase 24 – Clippy regression fix for Outbox API (Codex)
- [x] Fix `len_without_is_empty` on the public `Outbox` API
- [x] Re-run strict workspace clippy

## Review (Phase 24)
- Implemented:
  - Added `Outbox::is_empty()` to match the existing public `Outbox::len()` API and satisfy strict clippy settings.
- Verification:
  - `cargo clippy --workspace -- -D warnings`
