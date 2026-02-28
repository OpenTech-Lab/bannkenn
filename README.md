# BannKenn – Self-Hosted Collaborative Intrusion Prevention System

**BannKenn** is a modern, self-managed alternative to CrowdSec: an open-source, behavior-based Intrusion Prevention System (IPS) with lightweight agents for PCs and cloud servers, a central threat aggregation server, and a real-time web dashboard.

Built for privacy-focused users, homelabs, small teams, or anyone who wants full control without relying on external SaaS or community consoles.

## Goals & Philosophy
- **Fully self-hosted** — no mandatory external dependencies or data sharing
- **High-performance core** written in **Rust** (memory-safe, fast, concurrent)
- **Modern dashboard** built with **Next.js** (React, SSR, API routes)
- **Agent-based detection** on endpoints (Linux, Windows, macOS, cloud VMs)
- **Bootstrap with community threat intel** — import free/public IP blocklists
- Optional future: Add your own collaborative sharing (anonymized signals)

Similar in spirit to CrowdSec + Fail2Ban, but re-engineered from scratch for better safety and customizability.

## Architecture Overview

- **Agents**  
  Lightweight Rust binaries installed on protected hosts (PCs, servers, containers).  
  - Monitor logs (SSH, web servers, etc.) in real-time  
  - Detect patterns (brute-force, scans, anomalies)  
  - Enforce blocks via firewall (nftables, iptables, Windows Firewall)  
  - Report decisions/alerts to central server  
  - Cross-platform compilation

- **Central Server** (Rust + Actix-web / Axum)  
  - Aggregates alerts & decisions from agents  
  - Maintains local threat database (PostgreSQL / SQLite)  
  - Analyzes patterns, computes reputation scores  
  - Distributes global/local block decisions  
  - Secure API (TLS, JWT auth)

- **Dashboard** (Next.js)  
  - Web UI for monitoring agents, viewing alerts, editing rules  
  - Real-time updates (WebSockets / SSE)  
  - Visualizations: attack timelines, geo-maps, top attackers  
  - Rule editor (YAML-like scenarios)  
  - Deployable via Docker, Vercel, or self-hosted Node

- **Threat Intelligence**  
  Start with high-quality free community feeds (no CrowdSec hub required):  
  - **IPsum** (stamparm/ipsum) — daily aggregated feed with hit scores (30+ sources)  
    → https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt  
    (Filter by score ≥ 3–5 for low false positives)  
  - **FireHOL level1 / level2** — curated, safe-for-production blocklists  
    → https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset  
  - **DigitalSide Threat-Intel** — malware-related IPs in CSV  
    → https://osint.digitalside.it/Threat-Intel/csv/  
  - Others: LGOG Flagged_IP_List CSV, sefinek Malicious-IP-Addresses, Abuse.ch trackers

  Automate daily ingestion in Rust (reqwest + csv crate) to seed/enrich your local DB.

## Repo Structure

```
bannkenn/                          # repo root (e.g. github.com/toyofumi/bannkenn)
├── dashboard/                     # Next.js frontend + dashboard UI
│   ├── app/                       # App Router (Next.js 13+)
│   ├── components/
│   ├── lib/                       # API clients, types, utils
│   ├── public/
│   ├── styles/
│   ├── next.config.js
│   ├── package.json
│   ├── tsconfig.json
│   └── .env.local.example
├── agent/                         # Rust agent (the thing installed on protected hosts)
│   ├── Cargo.toml
│   ├── Cargo.lock
│   ├── src/
│   │   ├── main.rs
│   │   ├── config.rs
│   │   ├── detector.rs           # log parsers, pattern matchers
│   │   ├── bouncer.rs            # firewall integration
│   │   ├── client.rs             # talks to server
│   │   └── cache.rs              # local decision cache (sled / json / etc.)
│   └── build.rs                   # optional: embed version, etc.
├── server/                        # Rust central server (API, aggregator, decision engine)
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs
│   │   ├── api/                  # axum/actix-web routes
│   │   ├── models/
│   │   ├── db.rs                 # sqlx / diesel / etc.
│   │   ├── aggregator.rs         # threat scoring, merging
│   │   └── auth.rs
│   └── migrations/                # if using sqlx migrate or refinery
├── docker/                        # Dockerfiles & compose files
│   ├── Dockerfile.agent
│   ├── Dockerfile.server
│   └── docker-compose.yml         # dev: postgres + server + dashboard
├── scripts/                       # helper scripts
│   ├── install-agent.sh
│   └── release-agent.sh           # build binaries for linux/windows/macos
├── .github/
│   └── workflows/                 # CI: test rust, build binaries, lint next.js
├── README.md
├── .gitignore
└── LICENSE
```

### Why separate `agent/` and `server/` (instead of combining them)?

| Aspect                  | Agent (in `agent/`)                          | Server (in `server/`)                          |
|-------------------------|----------------------------------------------|------------------------------------------------|
| Purpose                 | Runs on many hosts, detects & blocks         | Central aggregator & decision maker            |
| Resource usage          | Very low (should run on tiny VMs/PCs)        | Higher (DB, more CPU/RAM possible)             |
| Distribution            | Single binary + install script               | Docker / systemd service / bare metal          |
| Dependencies            | Minimal (no DB client if possible)           | sqlx + postgres driver, possibly redis         |
| Build target            | Cross-compile for many platforms             | Usually linux/amd64 or arm64 only              |
| Update frequency        | Can be updated independently per host        | Updated once centrally                         |
| Testing                 | Unit + integration (mock server)             | Full API + DB tests                            |

Separating them early avoids coupling and makes it much easier later when you:
- Package the agent for Homebrew, Scoop, .deb/.rpm
- Run agents in Docker on cloud instances
- Scale the server separately (e.g. behind nginx + multiple replicas)

## Key Technologies
| Component      | Technology                  | Why?                              |
|----------------|-----------------------------|-----------------------------------|
| Agents & Server| Rust (tokio, axum/actix-web, sqlx, serde) | Safety, speed, no memory bugs    |
| Dashboard      | Next.js 14+ (App Router)    | Modern UI, SSR, easy API integration |
| Database       | PostgreSQL (or SQLite)      | Reliable storage for alerts/threats |
| Real-time      | WebSockets / Server-Sent Events | Live alert updates               |
| Deployment     | Docker Compose / Kubernetes | Easy scaling & self-hosting      |

## Getting Started (Planned MVP Roadmap)
1. Rust agent prototype: log tailing + basic pattern detection  
2. Simple central server + PostgreSQL  
3. Import community IP lists (cron job)  
4. Next.js dashboard skeleton + auth  
5. Agent ↔ Server communication (gRPC / REST + TLS)  
6. Firewall bouncer integration  
7. Add visualizations & rule editor

## Installation (Future)
```bash
# Agent (example Linux)
curl -sSL https://get.BannKenn.sh/agent | bash

# Server + Dashboard (Docker Compose)
git clone https://github.com/yourname/BannKenn
cd BannKenn
docker compose up -d
```

## Why Build This?
- CrowdSec is great but ties you to their ecosystem/console for full features.
- Rust reduces attack surface vs Go (CrowdSec's language).
- Full data sovereignty — keep everything on-prem.
- Easy to extend (custom parsers, ML scoring, your own sharing network).

## License
MIT (or choose your preference)

## Contributing
Welcoming issues, PRs, feedback! Especially on:
- OS-specific firewall integrations
- Low-FP detection scenarios
- Dashboard UX
