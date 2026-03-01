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
