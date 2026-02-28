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
