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

## Phase 16 – Investigate agent outbound-request blocking behavior (Codex)
- [x] Review project lessons and task history for prior firewall/network behavior decisions
- [x] Inspect agent firewall implementation for inbound vs outbound chain handling
- [x] Inspect agent HTTP client/runtime paths to confirm expected outbound server communication
- [x] Document the conclusion in this task file so the behavior is explicit

## Review (Phase 16)
- The agent does make outbound HTTP(S) requests to the configured dashboard/server using `reqwest` for registration, heartbeats, decision sync, telemetry, and updates.
- The firewall implementation only inserts drop rules for source IPs into inbound/forward paths:
  - nftables: dedicated `inet bannkenn` table with `input` and `forward` chains only
  - iptables: `INPUT` and `FORWARD` chains only
- No `OUTPUT` chain or egress-deny logic exists in the agent codebase, so BannKenn does not generally block outbound requests initiated by the host/agent.
- A blocked remote IP can still be dropped when it is the packet source on inbound/forward traffic, but the agent does not implement a general outbound request blocker.
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

## Phase 25 – Agent self-update command (Codex)
- [x] Inspect current install/update flow and release asset assumptions
- [x] Add `bannkenn-agent update [version]` to download and install the correct release asset
- [x] Restart the systemd service automatically when updating an active installed agent
- [x] Document and verify the update path with tests/checks

## Review (Phase 25)
- Findings:
  - The agent had no built-in update path; updates were still manual download + chmod + move + manual service restart.
  - Release asset naming was already stable enough to support a CLI updater without changing the server.
- Implemented:
  - Added `bannkenn-agent update [version]`
  - No version argument downloads the latest GitHub release for the current platform
  - Explicit versions like `bannkenn-agent update v1.3.18` or `bannkenn-agent update 1.3.18` are supported
  - The updater replaces the currently running binary path and restarts `bannkenn-agent` automatically if the systemd service is active
  - Updated README install docs to show the new command
- Verification:
  - `cargo fmt --all`
  - `cargo test -p bannkenn-agent updater -- --nocapture`
  - `cargo check --workspace`
  - `cargo clippy --workspace -- -D warnings`

## Phase 26 – Offline/restricted-network Docker server build (Codex)
- [x] Vendor Rust crates required by the workspace for Docker builds
- [x] Add cargo source replacement config and stop ignoring required lock/config files
- [x] Update the server container build/runtime path to avoid crates.io and apt during image build
- [x] Verify the server Docker build path without network dependency

## Review (Phase 26)
- Implemented:
  - Vendored the Rust workspace dependencies into `vendor/` and added `.cargo/config.toml` source replacement.
  - Stopped ignoring reproducibility-critical files such as `Cargo.lock` and `rust-toolchain.toml`; added `.dockerignore` to keep the Docker context tight.
  - Updated `docker/Dockerfile.server` to use vendored crates with `cargo build --frozen`, removed the builder/runtime `apt-get` steps, and copied the CA bundle from the builder stage.
  - Added `bannkenn-server healthcheck` and switched the server Compose healthcheck to use the binary instead of `wget`.
- Verification:
  - `cargo test -p bannkenn-server --frozen`
  - `cargo build --release --frozen --bin bannkenn-server`
  - `docker build --network none -f docker/Dockerfile.server -t bannkenn-server-offline-test .`
  - `docker run --rm --entrypoint sh bannkenn-server-offline-test -lc 'bannkenn-server >/tmp/server.log 2>&1 & pid=$!; sleep 2; bannkenn-server healthcheck; status=$?; kill $pid; wait $pid 2>/dev/null; exit $status'`

## Phase 27 – Restore dashboard availability on localhost:3021 (Codex)
- [x] Inspect the current listener/container state and reproduce the dashboard startup failure
- [x] Fix the immediate cause preventing the dashboard from serving on port 3021
- [x] Verify `http://localhost:3021/` responds successfully

## Review (Phase 27)
- Findings:
  - The compose stack was not running, so nothing was listening on `localhost:3021`.
  - After bringing it up, both containers were healthy internally, but host requests to `localhost:3021` and `localhost:3022` connected and then hung with no response.
  - Direct requests from inside the containers succeeded, which isolated the problem to the host-to-Docker bridge/forward path rather than the app processes themselves.
- Implemented:
  - Switched `docker/docker-compose.yml` to `network_mode: host` for both `server` and `dashboard` so they bind directly on the Linux host instead of relying on Docker bridge port publishing.
  - Updated the dashboard server URL to `http://127.0.0.1:3022` for host-networked containers.
  - Removed the obsolete Compose `version` key while touching the file.
- Verification:
  - `docker compose -f docker/docker-compose.yml up -d --build --force-recreate`
  - `curl -I http://127.0.0.1:3021`
  - `curl http://127.0.0.1:3021/api/health`
  - `docker compose -f docker/docker-compose.yml ps`

## Phase 28 – Remove BannKenn nftables rules on agent stop (Codex)
- [x] Inspect the current firewall lifecycle and confirm stop-time cleanup is missing
- [x] Add an idempotent firewall cleanup path for BannKenn-managed nftables state
- [x] Wire cleanup into agent shutdown and a manual CLI cleanup entrypoint
- [x] Update the installed systemd unit/docs to run cleanup on service stop
- [x] Verify with targeted Rust tests and syntax/build checks

## Review (Phase 28)
- Findings:
  - The agent created BannKenn nftables state on startup but had no teardown path on SIGTERM or `systemctl stop`, so the blocklist rules and set stayed active after the service exited.
  - The installer-generated unit also had no stop hook, so even a clean systemd stop relied on the process doing nothing special.
- Implemented:
  - Added `cleanup_firewall()` for BannKenn-managed nftables state in `agent/src/firewall.rs`.
  - Cleanup removes BannKenn drop rules from the `inet filter input` and `forward` chains by handle, then deletes the `bannkenn_blocklist` set. The path is idempotent and tolerant of already-missing nft objects.
  - Added `bannkenn-agent cleanup-firewall` and wired `run()` to catch `SIGTERM`/`Ctrl+C`, abort worker tasks, and remove BannKenn firewall state during shutdown.
  - Updated `scripts/install.sh` and the README systemd unit example to include `ExecStopPost=-/usr/local/bin/bannkenn-agent cleanup-firewall`.
  - Documented that stopping the service removes BannKenn-managed nftables rules.
- Verification:
  - `cargo fmt --all`
  - `bash -n scripts/install.sh`
  - `cargo check -p bannkenn-agent`
  - `cargo test -p bannkenn-agent`
  - Added firewall parser unit tests covering BannKenn rule-handle extraction for nft cleanup

## Phase 29 – README lifecycle docs for install/stop/uninstall/update (Codex)
- [x] Inspect current README lifecycle coverage and identify gaps/inconsistencies
- [x] Update README with explicit install, stop, uninstall, and update instructions
- [x] Verify command/path consistency in the revised README

## Review (Phase 29)
- Findings:
  - The README covered setup and agent updates, but it did not provide a single clear place for stop and uninstall operations.
  - The documented source install command pointed to `install.sh` in the repo root, but the actual installer lives at `scripts/install.sh`.
  - The documented Compose startup command omitted the repo’s actual compose file path under `docker/`.
- Implemented:
  - Updated the step-by-step setup flow to use `docker compose -f docker/docker-compose.yml up -d --build`.
  - Corrected the source installer command to `sudo bash scripts/install.sh`.
  - Added a `Common Operations` section to `README.md` covering install, stop, update, and uninstall for both the Docker stack and the Linux systemd agent.
  - Included explicit agent uninstall commands for stopping/disabling the service, cleaning up firewall state, removing the unit, deleting the binary, and removing local config.
- Verification:
  - Reviewed the updated README content and checked the command references with `rg` for:
    - `docker compose -f docker/docker-compose.yml`
    - `scripts/install.sh`
    - `systemctl stop bannkenn-agent`
    - `bannkenn-agent update`
    - `cleanup-firewall`

## Phase 30 – Move systemd service lifecycle into init/uninstall (Codex)
- [x] Inspect current init/install flow and define service lifecycle changes
- [x] Add CLI-managed systemd unit creation during `bannkenn-agent init`
- [x] Add CLI uninstall flow that disables and removes the service unit
- [x] Align installer and README with the new lifecycle
- [x] Verify with Rust checks/tests and shell syntax checks

## Review (Phase 30)
- Findings:
  - The service lifecycle was split awkwardly: `scripts/install.sh` created/enabled `bannkenn-agent.service`, while `bannkenn-agent init` only wrote config.
  - That split made the CLI less self-contained and forced the README/install flow to explain service creation separately from initialization.
- Implemented:
  - Added `agent/src/service.rs` with CLI-owned systemd unit rendering/install/removal helpers.
  - `bannkenn-agent init` now writes config and automatically installs `/etc/systemd/system/bannkenn-agent.service` on Linux/systemd when run with `sudo`.
  - Added `bannkenn-agent uninstall`, which stops/disables the service, removes the service file, reloads systemd, cleans up BannKenn-managed firewall state, removes local config, and deletes the running agent binary.
  - Simplified `scripts/install.sh` so it only installs the binary and points users to `bannkenn-agent init` for service creation.
  - Updated `README.md` to reflect the new `init` and `uninstall` lifecycle.
- Verification:
  - `cargo fmt --all`
  - `bash -n scripts/install.sh`
  - `cargo check -p bannkenn-agent`
  - `cargo test -p bannkenn-agent`
  - `rg -n "bannkenn-agent.service|sudo bannkenn-agent uninstall|enable --now bannkenn-agent|install the systemd unit" README.md scripts/install.sh agent/src -S`

## Phase 31 – Dashboard tabs for Recent Decisions and SSH Access Events (Codex)
- [x] Inspect the current home page layout for Recent Decisions and SSH Access Events
- [x] Merge the two sections into one shared tabbed panel
- [x] Verify the dashboard still builds after the UI change

## Review (Phase 31)
- Findings:
  - The home page rendered `SSH Access Events` and `Recent Decisions` as two separate blocks, which split related recent activity across the page.
- Implemented:
  - Added a local tab state on the dashboard home page.
  - Removed the standalone `SSH Access Events` block.
  - Replaced the old `Recent Decisions` block with a shared `Recent Activity` panel containing two tabs:
    - `Recent Decisions`
    - `SSH Access Events`
  - Preserved the existing table content and empty states, but now switches views in-place inside the same panel.
- Verification:
  - `cargo fmt --all`
  - `npm run build` in `dashboard/`

## Phase 32 – Reproduce reported cargo check failure (Codex)
- [x] Run the relevant cargo check commands against the current workspace
- [x] Verify broader target coverage to catch target-specific compile failures

## Review (Phase 32)
- Findings:
  - I could not reproduce a cargo compile failure in the current workspace state.
- Verification:
  - `cargo check -p bannkenn-agent`
  - `cargo check --workspace`
  - `cargo check --workspace --all-targets`
  - `cargo test -p bannkenn-agent`

## Phase 33 – Fix CI cargo resolution with missing vendor directory (Codex)
- [x] Inspect Cargo source replacement config and workflow behavior around `vendor/`
- [x] Stop forcing vendored dependencies for normal workspace/CI cargo commands
- [x] Preserve vendored source replacement for offline Docker server builds
- [x] Verify workspace cargo commands still pass after the config change

## Review (Phase 33)
- Findings:
  - CI failed because the repo-level `.cargo/config.toml` forced all Cargo invocations to use `vendor/`, but `vendor/` is not tracked in git and is therefore absent in clean GitHub Actions checkouts.
  - The vendored source replacement is only actually required for the offline server Docker build path, not for normal `cargo check`/`cargo test` in CI.
- Implemented:
  - Removed the repo-root `.cargo/config.toml` so normal workspace and CI Cargo commands resolve dependencies from crates.io again.
  - Added `docker/cargo-vendor-config.toml` and updated `docker/Dockerfile.server` to copy that file into `.cargo/config.toml` inside the build image, preserving vendored/offline Docker behavior where it is needed.
- Verification:
  - `cargo check --workspace`
  - `cargo check --workspace --all-targets`
  - Confirmed `docker/Dockerfile.server` now sources vendored Cargo config from `docker/cargo-vendor-config.toml`

## Phase 34 – Update release script to refresh Cargo.lock (Codex)
- [x] Inspect `scripts/release.sh` and confirm it only updates `Cargo.toml`
- [x] Patch the script to refresh/stage `Cargo.lock` during version bumps
- [x] Verify the lockfile update path in an isolated repo copy

## Review (Phase 34)
- Findings:
  - `scripts/release.sh` bumped the workspace version in `Cargo.toml` and created the changelog, but it never refreshed or staged `Cargo.lock`.
  - That left the lockfile package versions stale until a later manual Cargo command happened to rewrite them.
- Implemented:
  - Added a `Refreshing Cargo.lock` step to `scripts/release.sh`.
  - The script now runs `cargo check --workspace` immediately after the version bump and stages `Cargo.lock` if it changed.
- Verification:
  - `bash -n scripts/release.sh`
  - `cargo check --workspace`
  - Ran `scripts/release.sh 1.3.22` in an isolated temporary git repo with a local bare remote and confirmed the resulting release commit updated both `Cargo.toml` and `Cargo.lock`

## Phase 35 – Move nftables state into dedicated BannKenn table (Codex)
- [x] Inspect the current nftables implementation and identify legacy `inet filter` assumptions
- [x] Switch BannKenn-managed nftables state to a dedicated table with upgrade cleanup
- [x] Update related docs/comments/tests as needed
- [x] Verify with cargo checks/tests

## Review (Phase 35)
- Findings:
  - BannKenn was using the shared `inet filter` table, which kept the rule count low via a set but still mixed BannKenn state into the host’s main firewall namespace.
  - Existing installs could already have BannKenn-managed rules and the `bannkenn_blocklist` set in `inet filter`, so the new layout needed an upgrade cleanup path.
- Implemented:
  - Switched the active nftables backend to a dedicated `inet bannkenn` table in `agent/src/firewall.rs`.
  - BannKenn now creates its set and base chains inside that dedicated table, keeping its nft state isolated from the main `filter` table.
  - Cleanup now deletes the dedicated BannKenn table and also removes any legacy BannKenn rules/set previously installed into `inet filter`.
  - Updated comments and README wording to reflect the dedicated-table layout.
- Verification:
  - `cargo fmt --all`
  - `cargo check -p bannkenn-agent`
  - `cargo test -p bannkenn-agent`

## Phase 36 – Preserve localhost/local access when nftables updates (Codex)
- [x] Inspect the watcher + firewall path to confirm how local addresses can enter BannKenn enforcement
- [x] Add a shared firewall-level guard that refuses to enforce loopback/private/reserved addresses
- [x] Add regression tests covering loopback/local suppression and normal public-IP enforcement
- [x] Verify with targeted Rust tests/checks and document the results

## Review (Phase 36)
- Findings:
  - BannKenn could treat self-originated addresses as normal attackers because neither the detection pipeline nor the firewall layer filtered loopback/private/local ranges before adding them to the nftables set.
  - Once a local address such as `127.0.0.1` or a Docker bridge/private source entered the blocklist, host access to `http://localhost:3021`, `https://localhost`, and similar local services could be cut off by BannKenn’s own firewall rules.
- Implemented:
  - Added `should_skip_local_firewall_enforcement()` in `agent/src/firewall.rs` and used it as a hard guard before any firewall block operation.
  - Updated the watcher to ignore local/self-originated addresses before they can emit alert/block events or create sliding-window state.
  - Updated startup restore, sync, and runtime enforcement paths to skip local/reserved addresses and log that decision instead of touching nftables.
  - Added regression tests covering local/private suppression and loopback bypass of the block pipeline.
- Verification:
  - `cargo fmt --all`
  - `cargo check -p bannkenn-agent`
  - `cargo test -p bannkenn-agent`

## Phase 37 – Merge agent registration into init flow (Codex)
- [x] Inspect the current `init` / `connect` / `run` flow and confirm where registration and long-running runtime are coupled
- [x] Refactor agent registration into a shared helper that persists the JWT without starting the runtime loop
- [x] Make `bannkenn-agent init` attempt registration automatically and fall back cleanly if the server is unavailable
- [x] Make `bannkenn-agent connect` register-and-exit instead of starting the foreground agent loop
- [x] Update docs/tests and verify with Rust checks/tests

## Review (Phase 37)
- Findings:
  - The old workflow forced `init` and `connect` as separate commands, and `connect` immediately called `run()`, which made a one-time registration command behave like a foreground service.
  - That coupling was unnecessary because long-lived server communication already belongs to the running agent/service via heartbeat and sync loops; registration only needs to persist the JWT token.
- Implemented:
  - Extracted shared registration/token persistence into a reusable helper in `agent/src/main.rs`.
  - Changed `bannkenn-agent init` to attempt dashboard registration automatically after saving config and installing the systemd unit, while still leaving config usable if the server is temporarily unreachable.
  - Changed `bannkenn-agent connect` to register-and-exit instead of starting the foreground agent loop.
  - Updated README and installer messaging to reflect the new one-command setup path and the need to restart the service after token refreshes.
- Verification:
  - `cargo fmt --all`
  - `cargo check -p bannkenn-agent`
  - `cargo test -p bannkenn-agent`

## Phase 38 – Clarify updater restart behavior in docs (Codex)
- [x] Confirm whether `bannkenn-agent update` already restarts the active service
- [x] Make the README answer the manual-restart question explicitly
- [x] Capture the documentation lesson in `tasks/lessons.md`

## Review (Phase 38)
- Findings:
  - The updater already restarts `bannkenn-agent` automatically when the systemd service is active, but the README wording made that easy to miss when asking "do I need to restart manually?"
- Implemented:
  - Added explicit README language stating that no manual `systemctl restart` is needed after `sudo bannkenn-agent update` unless the service was inactive.
  - Recorded the lesson that operational docs should answer the exact next-step question directly, not only implicitly.
- Verification:
  - Code inspection: `agent/src/updater.rs`

## Phase 39 – Verify agent stays up after self-update restart (Codex)
- [x] Inspect the update, restart, and heartbeat paths to identify how `update` can leave an agent offline
- [x] Harden the updater so it verifies the systemd service remains active after restart
- [x] Surface a clearer update-time error when the service restarts but does not stay alive
- [x] Verify with Rust formatting/checks/tests

## Review (Phase 39)
- Findings:
  - The updater previously treated `systemctl restart bannkenn-agent` success as sufficient, but that only confirmed the restart command returned successfully, not that the agent stayed alive long enough to resume heartbeats.
  - That could leave the dashboard showing a heartbeat loss after update with no immediate updater-side signal about the failed steady state.
- Implemented:
  - Hardened `agent/src/updater.rs` so the updater polls `systemctl is-active` after restart and requires a short streak of active samples before reporting success.
  - If the restarted service does not stay active, the updater now returns an error that includes a `systemctl status --no-pager --full bannkenn-agent` snapshot.
  - Added a README troubleshooting note for the post-update offline case and recorded the lesson in `tasks/lessons.md`.
- Verification:
  - `cargo fmt --all`
  - `cargo check -p bannkenn-agent`
  - `cargo test -p bannkenn-agent`

## Phase 40 – Skip no-op self-update output when already latest (Codex)
- [x] Inspect the updater version-resolution path and confirm why it prints `-> latest`
- [x] Resolve the target release version before install and skip no-op updates
- [x] Record the updater UX lesson in `tasks/lessons.md`
- [x] Verify with Rust formatting/checks/tests

## Review (Phase 40)
- Findings:
  - The updater only derived a display label from the final download URL, which can collapse to `latest` and could not distinguish a real upgrade from a no-op latest-version check.
- Implemented:
  - Added target-version resolution before download/install, including a latest-release probe that extracts the actual release version from GitHub’s redirect.
  - The updater now exits early with `bannkenn-agent is already up to date (...)` when the current version already matches the requested/latest release, so it does not replace the binary or restart the service unnecessarily.
  - Added regression tests for release-version parsing and `v`-prefix-insensitive version comparison.
- Verification:
  - `cargo fmt --all`
  - `cargo check -p bannkenn-agent`
  - `cargo test -p bannkenn-agent updater`

## Phase 41 – Central whitelist for agent block bypass (Codex)
- [x] Inspect current server decision storage, agent sync/enforcement flow, and dashboard admin mutation paths
- [x] Add server-side whitelist storage and list/create/delete API endpoints
- [x] Update agent sync/enforcement to honor whitelist entries and remove local blocks for whitelisted IPs
- [x] Add dashboard whitelist list/editor UI with create/delete actions
- [x] Verify with targeted Rust/Next checks/tests and document the result

## Review (Phase 41)
- Implemented a central `whitelist_entries` server table with `GET /api/v1/whitelist`, `POST /api/v1/whitelist`, and `DELETE /api/v1/whitelist/:id`.
- New whitelist inserts now purge existing decision rows for that exact IP, and future decision inserts are skipped while the IP remains whitelisted.
- The agent now syncs whitelist entries, caches them offline, skips whitelist hits in the detection pipeline, skips server-synced decisions for whitelisted IPs, and actively removes existing local firewall blocks for whitelisted IPs on the next sync/startup.
- The dashboard home page now shows a whitelist section with add, note edit, and remove controls, backed by new Next.js API proxy routes.
- Verification:
  - `cargo fmt --all`
  - `cargo check --workspace`
  - `cargo test --workspace`
  - `npm run build` in `dashboard/`

## Phase 42 – Nginx TLS reverse-proxy path for BannKenn (Codex)
- [x] Add an nginx TLS example config for the current host-network BannKenn deployment
- [x] Document the no-domain IP+port setup and agent `server_url` guidance in README
- [x] Verify config syntax if nginx is available locally and record results

## Review (Phase 42)
- Added `deploy/nginx/bannkenn-tls.example.conf` for the current host-network deployment:
  - `https://SERVER_IP:1234` -> `127.0.0.1:3022` (BannKenn API)
  - `https://SERVER_IP:1235` -> `127.0.0.1:3021` (dashboard)
- Reused a single certificate across both TLS ports because they terminate on the same server IP.
- Added `deploy/nginx/generate-ip-cert.sh` to generate a self-signed IP-SAN certificate for nginx without requiring a domain.
- Updated `README.md` with the no-domain nginx/TLS flow, certificate generation command, and the correct agent `server_url` target (`https://SERVER_IP:1234`).
- Verified `deploy/nginx/generate-ip-cert.sh` with `bash -n` and by generating a temporary certificate whose SAN includes `IP Address:192.0.2.10`.
- Verified the nginx config with a disposable `nginx:alpine` container running `nginx -t -c /etc/nginx/nginx.conf`.

## Phase 43 – Docker Compose nginx TLS service (Codex)
- [x] Add an nginx service to `docker/docker-compose.yml` that fits the host-network deployment
- [x] Document the compose-managed TLS startup flow and certificate directory handling in README
- [x] Verify the compose file and nginx service configuration

## Review (Phase 43)
- Added an opt-in `nginx` service to `docker/docker-compose.yml` under the `tls` profile.
- The nginx container uses `network_mode: host` so it can proxy to `127.0.0.1:3022` and `127.0.0.1:3021` while listening on host `1234` and `1235`.
- Mounted the existing nginx config from `deploy/nginx/bannkenn-tls.example.conf` and the certificate directory from `${BANNKENN_NGINX_SSL_DIR:-/etc/nginx/ssl}`.
- Kept the default `docker compose up -d --build` behavior as HTTP-only so users without certificates are not forced into a broken TLS startup.
- Updated `README.md` to document the exact TLS startup command: `docker compose -f docker/docker-compose.yml --profile tls up -d --build`.
- Verified compose resolution with:
  - `docker compose -f docker/docker-compose.yml config`
  - `docker compose -f docker/docker-compose.yml --profile tls config`

## Phase 44 – Multi-address TLS certificate guidance (Codex)
- [x] Extend the nginx certificate helper to support multiple SAN IPs/hostnames
- [x] Document that agent/browser addresses must match the certificate SAN entries
- [x] Verify multi-SAN certificate generation works as expected

## Review (Phase 44)
- Extended `deploy/nginx/generate-ip-cert.sh` so it accepts multiple SAN entries plus an optional `--out-dir` flag.
- Kept backward compatibility with the old two-argument form: `generate-ip-cert.sh 192.0.2.10 /etc/nginx/ssl`.
- Updated `README.md` to show both single-IP and LAN+public-IP certificate generation examples.
- Verified with:
  - `bash -n deploy/nginx/generate-ip-cert.sh`
  - generating a certificate for the required SAN entries including `123.123.123.123`
  - inspecting the certificate SANs with `openssl x509 -text`

## Phase 45 – Agent custom CA trust for self-signed TLS (Codex)
- [x] Add agent config support for a custom PEM CA/certificate path
- [x] Use the custom CA path for `connect` and runtime API clients
- [x] Document the self-signed agent workflow in README
- [x] Verify the updated agent crate with compile/test coverage

## Review (Phase 45)
- Added `ca_cert_path` to `AgentConfig` so self-signed HTTPS servers can be trusted from a specific PEM file without modifying the whole system trust store.
- Replaced bare `reqwest::Client::new()` construction with a shared builder that loads the configured PEM certificate when present.
- Updated `connect` registration failures to turn `UnknownIssuer` into a clearer remediation message.
- Updated `init` to prompt for an optional custom CA/cert PEM path whenever the server URL is `https://...`.
- Updated `README.md` with `ca_cert_path` examples and `UnknownIssuer` remediation.
- Verified with:
  - `cargo check -p bannkenn-agent`
  - `cargo test -p bannkenn-agent`

## Phase 46 – Trust-on-first-use HTTPS pinning for agents (Codex)
- [x] Add agent-side certificate fetch/pin support for self-signed HTTPS servers
- [x] Wire TOFU into `connect`/`init` when HTTPS fails with `UnknownIssuer`
- [x] Document the new TOFU flow and verify the updated agent crate

## Review (Phase 46)
- Added `agent/src/tofu.rs` to fetch the presented certificate over a rustls handshake, compute its SHA-256 fingerprint, and save it as a pinned PEM under `~/.config/bannkenn/certs/`.
- Updated `connect` so an `UnknownIssuer` failure on HTTPS with no configured `ca_cert_path` now offers an interactive trust-on-first-use prompt instead of requiring a manual certificate copy first.
- Kept the explicit `ca_cert_path` path working for operators who prefer manual certificate distribution or a private CA bundle.
- Updated `README.md` to describe the TOFU flow and the pinned-certificate storage path.
- Verified with:
  - `cargo check -p bannkenn-agent`
  - `cargo test -p bannkenn-agent`
  - `cargo fmt --all`

## Phase 47 – Release workflow upload race fix (Codex)
- [x] Inspect the GitHub release workflow for the binary upload failure mode
- [x] Restructure release publishing to avoid concurrent uploads to the same GitHub release
- [x] Verify the updated workflow definition locally and record the result

## Review (Phase 47)
- Root cause: the old matrix job had every target call `softprops/action-gh-release` directly against the same release, which is prone to GitHub API retry/collision failures during concurrent asset uploads.
- Split the workflow into:
  - `release-build`: matrix build job that packages each binary and uploads it as a GitHub Actions artifact
  - `release-publish`: single publisher job that downloads all artifacts and performs one `softprops/action-gh-release` upload
- Added `strategy.fail-fast: false` so one build target does not automatically cancel the others before artifact collection completes.
- Verified the updated workflow with:
  - a local YAML parse via `python3` / `yaml.safe_load`
  - manual inspection of the new job graph and action references

## Phase 48 – Release cleanup on failed publish (Codex)
- [x] Update publish workflow so failed uploads do not leave a GitHub release behind
- [x] Verify the updated workflow definition locally and record the result

## Review (Phase 48)
- Updated `release-publish` so the GitHub release is created as a draft first.
- If the asset upload step fails, the workflow now runs `gh release delete <tag> --cleanup-tag=false` to remove the broken draft release while preserving the git tag.
- Only after a successful upload does the workflow publish the release with `gh release edit <tag> --draft=false`.
- Verified the updated workflow with a local YAML parse and manual inspection of the new publish/cleanup step ordering.

## Phase 49 – Native TLS for BannKenn server API (Codex)
- [x] Inspect the current server/runtime setup and confirm the cleanest native TLS path for the API
- [x] Add optional native TLS support to `bannkenn-server` while keeping plain HTTP fallback
- [x] Support a separate loopback-only plain HTTP bind for the local dashboard when native TLS is enabled
- [x] Update Docker Compose and README to document native TLS as the preferred API path and nginx as optional
- [x] Verify the updated server build/tests and record the result

## Review (Phase 49)
- Added optional native TLS support directly to `bannkenn-server` with new config/env fields:
  - `tls_cert_path`
  - `tls_key_path`
  - `local_bind`
- The server now:
  - serves HTTPS on the main `bind` address when both TLS paths are configured
  - keeps plain HTTP fallback when TLS is not configured
  - can expose a second loopback-only plain HTTP listener for the local dashboard and local healthchecks
- Updated Docker Compose so operators can enable native TLS by setting:
  - `BANNKENN_SERVER_TLS_DIR`
  - `BANNKENN_TLS_CERT_PATH`
  - `BANNKENN_TLS_KEY_PATH`
  - `BANNKENN_LOCAL_BIND`
  - `BANNKENN_DASHBOARD_SERVER_URL`
- Reframed README guidance so native TLS on the API is the recommended path when the dashboard stays local, while keeping the nginx `tls` profile documented as optional.
- Clarified the agent prompt text from "Dashboard server URL" to "BannKenn API server URL" to match the actual API endpoint agents must use.
- Verification:
  - `cargo fmt --all`
  - `cargo check --workspace`
  - `cargo test --workspace`
  - `docker compose -f docker/docker-compose.yml config`
  - `docker compose -f docker/docker-compose.yml --profile tls config`
  - `env BANNKENN_SERVER_TLS_DIR=/etc/bannkenn/tls BANNKENN_TLS_CERT_PATH=/etc/bannkenn/tls/bannkenn.crt BANNKENN_TLS_KEY_PATH=/etc/bannkenn/tls/bannkenn.key BANNKENN_LOCAL_BIND=127.0.0.1:3023 BANNKENN_DASHBOARD_SERVER_URL=http://127.0.0.1:3023 docker compose -f docker/docker-compose.yml config`

## Phase 50 – Sync vendored crates for Docker frozen builds (Codex)
- [x] Inspect the Docker failure and confirm it is caused by vendor/ drifting from Cargo.lock
- [x] Refresh the vendored crate tree to include the new server dependency graph cleanly
- [x] Verify the offline frozen server build and the full Docker Compose build/start path

## Review (Phase 50)
- Root cause: `server/Cargo.toml` gained the Hyper 1.x / rustls server stack, but the checked-in `vendor/` tree was not regenerated for the new `Cargo.lock`, so Docker's offline `cargo build --frozen` could not resolve `h2 v0.4.13`.
- Initial `cargo vendor --locked vendor` fixed the missing crates but still left a Docker-only checksum collision around `vendor/h2` vs `vendor/h2-0.3.27`.
- Regenerated the vendor tree with `cargo vendor --locked --versioned-dirs` and replaced the repo `vendor/` directory with that clean versioned tree to eliminate ambiguous mixed-version directory names.
- Verification:
  - `cargo build --release --frozen --bin bannkenn-server --config 'source.crates-io.replace-with="vendored-sources"' --config 'source.vendored-sources.directory="vendor"'`
  - `docker compose -f docker/docker-compose.yml up -d --build server dashboard`
  - `docker compose -f docker/docker-compose.yml ps`

## Phase 51 – Fix init freeze after TOFU prompt (Codex)
- [x] Inspect why `bannkenn-agent init` freezes after certificate trust while `connect` does not
- [x] Fix the stdin handling so init can complete the registration retry after TOFU
- [x] Verify the agent crate and document the outcome
- Root cause: `init()` held a locked `stdin` reader through the setup prompts, then handed off to TOFU code that prompted again via `io::stdin()`, so the follow-up trust input appeared but the retry path blocked behind the still-live lock.
- Fix: explicitly `drop(reader)` in `init()` immediately after the setup prompts and before `register_and_persist_agent()` so TOFU and later connect prompts can reuse stdin normally.
- Verification:
  - `cargo fmt --all`
  - `cargo check -p bannkenn-agent`
  - `cargo test -p bannkenn-agent`

## Phase 52 – Add one-command native TLS compose startup helper (Codex)
- [x] Inspect the existing installer and decide how to add a server-native-TLS startup mode without breaking agent installation
- [x] Implement the helper flow so generated certs can be reused with one script invocation
- [x] Update README and verify script syntax plus compose resolution
- Added a `server-native-tls` mode to `scripts/install.sh` that validates `bannkenn.crt` and `bannkenn.key`, injects the correct Docker Compose env vars for native TLS, and starts `server` plus `dashboard` with one command.
- Kept the default `scripts/install.sh` behavior unchanged for source installation of `bannkenn-agent`, so existing install workflows are unaffected.
- Updated the README native TLS section to recommend the one-command helper first and keep the manual `export ... && docker compose up ...` flow as an explicit equivalent.
- Verification:
  - `bash -n scripts/install.sh`
  - `bash scripts/install.sh --help`
  - `bash scripts/install.sh server-native-tls --help`
  - `env BANNKENN_SERVER_TLS_DIR=/etc/nginx/ssl BANNKENN_TLS_CERT_PATH=/etc/bannkenn/tls/bannkenn.crt BANNKENN_TLS_KEY_PATH=/etc/bannkenn/tls/bannkenn.key BANNKENN_LOCAL_BIND=127.0.0.1:3023 BANNKENN_DASHBOARD_SERVER_URL=http://127.0.0.1:3023 docker compose -f docker/docker-compose.yml config`

## Phase 53 – Handle overlapping CIDR/IP nftables restores (Codex)
- [x] Inspect the current agent firewall restore/apply flow and confirm how overlapping CIDR + host entries fail in nftables
- [x] Add an overlap-aware effective-block normalization path so broader CIDRs and covered hosts reconcile cleanly
- [x] Add regression tests for overlapping subnet/host decisions and verify with Rust formatting/checks/tests
- [x] Document the review outcome and any reusable lesson after verification

## Review (Phase 53)
- Root cause:
  - The agent stores block decisions as raw strings and can legitimately receive both CIDRs and single IPs for the same range.
  - BannKenn’s nftables set is an interval set, so replaying `101.47.142.48` after `101.47.142.0/24` or adding the `/24` after the host entry causes nft to reject the second insert with `interval overlaps with an existing one`.
  - The previous agent logic replayed decisions one-by-one and only treated `File exists` as benign, so restore/sync/runtime enforcement could warn or fail depending on insertion order.
- Implemented:
  - Added block-pattern parsing and canonicalization in `agent/src/firewall.rs` so overlapping CIDR/IP entries collapse to a deterministic effective set before nftables enforcement.
  - Added firewall reconciliation that removes superseded narrow entries before adding broader CIDRs, and reused that reconcile path for cached restore, startup sync, server sync updates, and runtime block/listed enforcement.
  - Extended watcher matching so CIDR-backed decisions count as already listed/enforced for covered IPs instead of only exact-string matches.
  - Added regression tests covering overlap collapse, CIDR coverage checks, CIDR source matching, and local CIDR skip handling.
- Verification:
  - `cargo fmt --all`
  - `cargo check -p bannkenn-agent`
  - `cargo test -p bannkenn-agent`

## Phase 54 – Make whitelist override broader firewall CIDR blocks (Codex)
- [x] Confirm why exact-IP whitelist entries do not override broader CIDR firewall blocks
- [x] Add firewall-managed whitelist enforcement so whitelisted IPs are accepted before blocklist drops
- [x] Add regression coverage and verify with Rust formatting/checks/tests
- [x] Document the review outcome after verification

## Review (Phase 54)
- Root cause:
  - The whitelist API stores exact IPs only, but the firewall can still contain broader CIDR blocks such as `203.0.113.0/24`.
  - The agent’s old whitelist handling only removed exact-match block entries, so a whitelisted host stayed blocked whenever the active firewall rule came from a covering CIDR instead of the same exact IP string.
- Implemented:
  - Added a dedicated firewall allowlist path in `agent/src/firewall.rs` for both nftables and iptables.
  - nftables now creates a managed `bannkenn_allowlist` set plus `accept` rules ahead of BannKenn’s drop rules, so an exact whitelisted IP overrides a broader CIDR block cleanly.
  - iptables now manages explicit `ACCEPT` rules ahead of BannKenn’s `DROP` rules for the same reason.
  - Added whitelist reconciliation state to the agent startup/sync flow and a runtime helper that immediately re-applies the allow override when a whitelisted IP is encountered.
- Verification:
  - `cargo fmt --all`
  - `cargo check -p bannkenn-agent`
  - `cargo test -p bannkenn-agent`

## Phase 55 – Support CIDR whitelist entries (Codex)
- [x] Confirm every exact-match whitelist assumption across server API/storage and agent enforcement
- [x] Allow canonical CIDR whitelist entries in the server API and make server-side whitelist checks CIDR-aware
- [x] Update agent whitelist matching and firewall allow reconciliation to honor CIDR entries end-to-end
- [x] Add regression coverage, verify with formatting/checks/tests, and document the outcome

## Review (Phase 55)
- Root cause:
  - Whitelist handling was still based on exact-string IP equality across the server API, DB checks, agent sync filters, and agent runtime detection.
  - That meant CIDR entries such as `221.103.201.0/24` could not be created at all, and even if stored manually they would not consistently suppress covered IPs/decision patterns.
- Implemented:
  - Added CIDR-aware IP pattern parsing/canonicalization on the server, so whitelist POSTs can accept exact IPs or CIDRs and normalize them to canonical network form.
  - Updated server-side whitelist checks to skip decisions when a whitelist entry fully covers the incoming decision pattern, and updated whitelist insertion cleanup to remove only decisions fully covered by the new whitelist entry.
  - Updated the agent to treat whitelist entries as patterns: covered source IPs are ignored in the watcher/runtime path, covered decision patterns are skipped during sync/restore, and firewall allow reconciliation now supports exact IPs plus CIDR ranges.
  - Updated the dashboard whitelist copy/input placeholder to reflect IP-or-CIDR support.
- Semantics:
  - Whitelist CIDR `203.0.113.0/24` covers exact IPs like `203.0.113.44` and narrower CIDRs inside that `/24`.
  - Exact whitelist IP `203.0.113.44` does not remove or suppress a broader block like `203.0.113.0/24`; instead the agent’s firewall allowlist overrides that exact host locally.
  - Non-canonical input like `123.123.123.123/24` is accepted and stored canonically as `123.123.123.0/24`.
- Verification:
  - `cargo fmt --all`
  - `cargo check --workspace`
  - `cargo test --workspace`

## Phase 56 – Verify offline timestamp continuity claim (Codex)
- [x] Inspect the agent event, outbox, and API payload path for original-event timestamp preservation
- [x] Inspect the server persistence layer for which timestamp is stored on receipt
- [x] Inspect dashboard rendering to confirm which timestamp field is displayed
- [x] Document the precise product statement that matches the current implementation

## Review (Phase 56)
- Findings:
  - The agent does capture a detection timestamp in memory on `SecurityEvent.timestamp`, and it logs that value locally when handling the event.
  - The durable outbox persists decisions, telemetry, and SSH-login events, so queued uploads survive temporary server outages and agent restarts.
  - The outbox payloads and API requests do not include an original event timestamp for decisions, telemetry, or SSH-login events.
  - The server writes `created_at = Utc::now()` when it receives those events, and the dashboard renders that stored `created_at` field.
- Consequence:
  - The dashboard currently shows server receipt time, not the original detection time on the agent.
  - Buffered events therefore appear delayed or bunched after an outage instead of forming a continuous original-event timeline.
  - Events that happened while the agent process itself was down are still missed entirely.
- Verification:
  - Code inspection of `agent/src/main.rs`, `agent/src/outbox.rs`, `agent/src/client.rs`, `server/src/routes/{decisions,telemetry,ssh_logins}.rs`, `server/src/db.rs`, `dashboard/app/page.tsx`, and `dashboard/app/agents/[id]/page.tsx`

## Phase 57 – Preserve original agent event timestamps through offline buffering (Codex)
- [x] Add timestamp fields to agent outbox payloads and API requests with backward compatibility for existing queued items
- [x] Persist agent-provided event timestamps on the server for decisions, telemetry, and SSH login events
- [x] Change dashboard-facing decision/telemetry/SSH queries to order by event timestamp rather than insert id
- [x] Add regression coverage for timestamp preservation and ordering
- [x] Verify with formatting, checks, and tests

## Review (Phase 57)
- Root cause:
  - The agent generated `SecurityEvent.timestamp`, but dropped it before durable outbox serialization and before HTTP requests to the server.
  - The server stored `created_at` as receipt time with `Utc::now()`, and dashboard-facing decision/telemetry queries sorted by insert `id`, so delayed uploads appeared bunched at outage-recovery time instead of their original event time.
- Implemented:
  - Added optional timestamp fields to agent outbox payloads and HTTP report bodies for decisions, telemetry, and SSH login events, while keeping old outbox files readable by treating missing timestamps as `None`.
  - The agent now queues the event’s original `SecurityEvent.timestamp` with every outbound decision, telemetry, and SSH login report.
  - Added server-side timestamp normalization so provided RFC3339 timestamps are stored as the event `created_at`; when absent or invalid, the server falls back to current receipt time for backward compatibility.
  - Updated dashboard-facing list queries for decisions, per-agent decisions, telemetry, per-agent telemetry, and SSH logins to order by `created_at DESC, id DESC` so delayed uploads render in timeline order.
  - Added decision, telemetry, SSH-login, and legacy-outbox regression tests for preserved timestamps and ordering.
- Result:
  - If an agent remains running while the server is offline, buffered events now appear on the dashboard as a continuous original-event timeline once connectivity is restored.
  - Older agents or old queued items without timestamps still work, but they continue to use server receipt time until upgraded and re-queued under the new format.
- Verification:
  - `cargo fmt --all`
  - `cargo check --workspace`
  - `cargo test --workspace`

## Phase 58 – Diagnose HTTPS-to-HTTP agent connect mismatch clearly (Codex)
- [x] Detect the rustls plaintext-on-TLS failure mode during agent registration/connect
- [x] Return a clear actionable error telling the operator to use `http://` or enable TLS on the server port
- [x] Add regression coverage and verify with formatting/checks/tests

## Review (Phase 58)
- Root cause:
  - `bannkenn-agent connect` attempted a TLS handshake because the configured `server_url` started with `https://`.
  - The reported rustls error `received corrupt message of type InvalidContentType` is the plaintext-on-TLS failure mode, which means the remote port is speaking plain HTTP instead of HTTPS/TLS.
  - BannKenn previously surfaced that raw transport error unchanged, which made the operator-facing diagnosis unclear.
- Implemented:
  - Added a dedicated error classifier in the agent connect path for plaintext-on-TLS handshake failures such as `InvalidContentType`.
  - `connect`/registration now returns a direct message telling the operator that the configured `https://` URL is hitting a plain HTTP listener and to either switch to `http://` or enable TLS on that server port.
  - Added regression tests for positive and negative classification cases.
- Verification:
  - `cargo fmt --all`
  - `cargo check -p bannkenn-agent`
  - `cargo test -p bannkenn-agent`

## Phase 59 – Add one-command dashboard stack setup helper (Codex)
- [x] Extend `scripts/install.sh` with a plain dashboard/server stack mode for normal HTTP deployments
- [x] Keep the native-TLS dashboard/server helper flow available and align naming/help output
- [x] Update README to document the new one-command dashboard setup path
- [x] Verify script syntax/help and compose configuration paths

## Review (Phase 59)
- Root cause:
  - `scripts/install.sh` only handled agent installation and the native-TLS compose helper, so there was no matching one-command helper for the common plain-HTTP dashboard/server stack.
  - Operators had to remember raw `docker compose up` plus the right environment shape, and stale TLS environment variables could accidentally leak into later HTTP starts.
- Implemented:
  - Added a new `dashboard` mode to `scripts/install.sh` that starts the `server` + `dashboard` compose stack in plain HTTP mode.
  - The new helper explicitly clears TLS-related compose env vars and sets the dashboard upstream to `http://127.0.0.1:3022`, preventing stale TLS settings from breaking the normal HTTP startup path.
  - Renamed the native-TLS helper path in the help/docs to `dashboard-native-tls` while keeping `server-native-tls` as a backward-compatible alias.
  - Updated the README so the primary dashboard setup flow is now a one-command script path for both HTTP and native-TLS deployments.
- Verification:
  - `bash -n scripts/install.sh`
  - `bash scripts/install.sh --help`
  - `bash scripts/install.sh dashboard --help`
  - `bash scripts/install.sh dashboard-native-tls --help`
  - `env BANNKENN_TLS_CERT_PATH= BANNKENN_TLS_KEY_PATH= BANNKENN_LOCAL_BIND= BANNKENN_DASHBOARD_SERVER_URL=http://127.0.0.1:3022 docker compose -f docker/docker-compose.yml config`
  - `env BANNKENN_SERVER_TLS_DIR=/etc/bannkenn/tls BANNKENN_TLS_CERT_PATH=/etc/bannkenn/tls/bannkenn.crt BANNKENN_TLS_KEY_PATH=/etc/bannkenn/tls/bannkenn.key BANNKENN_LOCAL_BIND=127.0.0.1:3023 BANNKENN_DASHBOARD_SERVER_URL=http://127.0.0.1:3023 docker compose -f docker/docker-compose.yml config`

## Phase 60 – Auto-generate TLS certs for dashboard-native-tls helper (Codex)
- [x] Inspect the existing certificate generator and why dashboard-native-tls fails on a fresh host
- [x] Extend `scripts/install.sh` so dashboard-native-tls can generate a self-signed cert when missing
- [x] Update README paths/examples to the actual generator location and new helper behavior
- [x] Verify script syntax/help and the certificate generation path

## Review (Phase 60)
- Root cause:
  - `dashboard-native-tls` assumed `bannkenn.crt` and `bannkenn.key` already existed, so a fresh host failed immediately instead of helping the operator create them.
  - The repo already had a certificate generator, but it lives at `scripts/generate-ip-cert.sh` while the README still referenced an older path.
- Implemented:
  - Added `--tls-san` and `--regenerate-cert` options to `dashboard-native-tls`.
  - When the TLS cert/key are missing, the helper now auto-generates a self-signed certificate into the requested TLS directory.
  - The helper uses explicit `--tls-san` values when provided, otherwise it falls back to auto-detected local IP/hostname SANs and prints what it generated.
  - Updated the README to reference `scripts/generate-ip-cert.sh` and document that `dashboard-native-tls` can generate the certs automatically.
- Verification:
  - `bash -n scripts/install.sh`
  - `bash scripts/install.sh --help`
  - `bash scripts/install.sh dashboard-native-tls --help`
  - `bash scripts/generate-ip-cert.sh --out-dir /tmp/... 127.0.0.1 123.123.123.123`

## Phase 61 – Keep systemd agent runtime aligned with `sudo bannkenn-agent connect` state (Codex)
- [x] Inspect how the systemd unit chooses the agent binary path and runtime home/config directory
- [x] Update the generated unit so the service uses the canonical installed agent binary and root config home
- [x] Refresh the systemd unit from `connect` so post-registration restarts pick up the correct runtime
- [x] Verify with agent formatting/tests

## Review (Phase 61)
- Root cause:
  - `sudo bannkenn-agent connect` writes the token and pinned certificate into root’s state under `/root/.config/bannkenn`, but the systemd unit did not explicitly pin the runtime home/config directory.
  - The unit also followed whatever path the binary happened to run from during `init`, so service execution could drift away from the canonical installed `/usr/local/bin/bannkenn-agent` binary after upgrades or ad-hoc runs.
  - That mismatch creates a service-only failure mode where manual `connect` succeeds, but the long-running service still runs the wrong binary and/or looks in the wrong place for `agent.toml` and pinned certs, so heartbeats never resume.
- Implemented:
  - Updated the generated systemd unit to wait for `network-online.target`, run explicitly as root, set `WorkingDirectory=/root`, and export `HOME=/root` plus `XDG_CONFIG_HOME=/root/.config`.
  - The unit now prefers the canonical installed binary at `/usr/local/bin/bannkenn-agent` when present and uses an explicit `run` subcommand for clarity.
  - `bannkenn-agent connect` now refreshes the systemd unit after successful registration so a subsequent restart uses the current binary/config path without requiring a separate `init`.
- Verification:
  - `cargo fmt --all`
  - `cargo test -p bannkenn-agent`

## Phase 62 – Add dashboard IP lookup page (Codex)
- [x] Inspect current decision, telemetry, and community-feed data paths and define the IP lookup response shape
- [x] Add a server IP lookup endpoint that returns local block history, per-machine event history, and matching community feed entries
- [x] Add a dashboard API proxy and a new page with IP input + result sections for summary, machine history, and community matches
- [x] Add navigation to the new page and keep the UI consistent with the existing dashboard
- [x] Verify with Rust tests/checks and a dashboard production build

## Review (Phase 62)
- Root cause:
  - There was no dedicated way in the dashboard to inspect a single IP across local detections, block decisions, multiple agents, and ingested community feeds.
  - Existing community aggregation in the server treated anything whose source was not literally `"agent"` as community data, which could misclassify agent-originated decisions because real agent sources are agent names.
- Implemented:
  - Added `GET /api/v1/ip-lookup?ip=...` on the server, backed by a new DB lookup that returns:
    - exact-IP local telemetry history
    - exact-IP local decision history
    - per-machine summaries across agents
    - community feed matches that work for both exact feed IPs and covering CIDRs
  - Added a dashboard proxy route at `dashboard/app/api/ip-lookup/route.ts`.
  - Added a new `/lookup` dashboard page with:
    - IP search input
    - status/geo summary
    - per-machine history table
    - local risk event table
    - local block decision table
    - community list match table
  - Added `IP Lookup` to the global navigation.
  - Corrected community query classification in the server so feed views exclude agent sources and campaign auto-blocks, and aligned the home dashboard’s local-decision filter with FireHOL feed sources.
  - Wrapped the lookup page’s `useSearchParams()` usage in `Suspense` so Next.js static prerendering succeeds in production builds.
- Verification:
  - `cargo fmt --all`
  - `cargo test -p bannkenn-server`
  - `npm run build` (in `dashboard/`)

## Phase 63 – Add agent connectivity diagnostic command (Codex)
- [x] Inspect the current agent connect/heartbeat flow and define the diagnostic sequence/output
- [x] Add a CLI command that tests DNS, TCP reachability, public health, and authenticated heartbeat with actionable failure classification
- [x] Verify with formatting/tests and document the outcome

## Review (Phase 63)
- Root cause:
  - BannKenn had `connect` for registration and the runtime heartbeat loop, but no operator-facing diagnostic command to separate DNS, TCP, TLS trust, reverse-proxy/Cloudflare responses, and heartbeat auth failures.
  - When access failed, operators had to infer from a single high-level error whether the problem was name resolution, transport reachability, HTTPS-vs-HTTP mismatch, certificate trust, or a proxy/origin rejection.
- Implemented:
  - Added a new agent CLI subcommand: `bannkenn-agent connecttest` with `connect-test` as a visible alias.
  - The command now:
    - loads the configured `server_url`, token, and optional `ca_cert_path`
    - resolves DNS for the configured host/port
    - attempts a direct TCP connection to the resolved addresses
    - probes `GET /api/v1/health`
    - probes `POST /api/v1/agents/heartbeat` with the saved JWT token
  - Added actionable diagnostics for:
    - DNS lookup failure
    - TCP connection failure
    - TLS trust failure (`UnknownIssuer`)
    - HTTPS pointed at a plain-HTTP port (`InvalidContentType` and related signatures)
    - unexpected HTTP responses, including explicit Cloudflare/proxy detection via response headers
    - missing or rejected JWT tokens during heartbeat
  - Added unit coverage for the new command parsing surface and Cloudflare response classification.
- Verification:
  - `cargo fmt --all`
  - `cargo test -p bannkenn-agent`
  - `cargo run -p bannkenn-agent -- connecttest --help`

## Phase 64 – Scrub exposed IPs from current files (Codex)
- [x] Search the working tree for exposed IP occurrences and identify current-file references
- [x] Replace exposed IP text with `123.123.123.123` or neutral wording where a second real address was only illustrative
- [x] Verify the working tree no longer contains the exposed IP values

## Review (Phase 64)
- Root cause:
  - The repo still contained the exposed IP in current tracked files outside historical commits, including docs, scripts, tests, and task notes.
  - Rewriting history alone would not fix the live working tree if those current references remained.
- Implemented:
  - Replaced the exposed IP in `README.md`, `scripts/install.sh`, `server/src/ip_pattern.rs`, `agent/src/tofu.rs`, and `tasks/todo.md`.
  - Updated the SAN-mismatch wording in `README.md` to avoid embedding a second specific IP while still explaining the failure mode.
- Verification:
  - `cargo test -p bannkenn-server ip_pattern::tests::canonicalizes_cidr_to_network_boundary`
  - `cargo test -p bannkenn-agent tofu::tests::sanitize_host_port_replaces_non_alnum`
