# BannKenn – Self-Hosted Collaborative Intrusion Prevention System

**BannKenn** is a modern, fully open-source, self-managed alternative to CrowdSec.

It is a behavior-based Intrusion Prevention System (IPS) with lightweight agents for PCs and cloud servers, a central threat aggregation server, and a real-time web dashboard.

Built for privacy-focused users, homelabs, small teams, and anyone who wants complete control without relying on external SaaS or community consoles.

## Goals & Philosophy
- **Fully self-hosted** — no mandatory external dependencies or data sharing
- High-performance core written in **Rust** (memory-safe, fast, concurrent)
- Modern dashboard built with **Next.js** (React, SSR, API routes)
- Agent distributed and installed via **npm** (published automatically by GitHub Actions)
- Bootstrap with community threat intel — import free/public IP blocklists
- Optional future: Add your own collaborative sharing (anonymized signals)

Similar in spirit to CrowdSec + Fail2Ban, but re-engineered from scratch for better safety and customizability.

## Architecture Overview

- **Agents** (`agent/`)
  Lightweight Rust binaries that run on protected hosts (PCs, servers, containers).  
  - Monitor logs (SSH, web servers, etc.) in real-time  
  - Detect patterns (brute-force, scans, anomalies)  
  - Enforce blocks via firewall (nftables, iptables, Windows Firewall)  
  - Report decisions/alerts to central server  
  - Cross-platform (Linux, Windows, macOS)  
  - **Installed via npm** (`npm install -g bannkenn-agent`) — GitHub Actions automatically builds and publishes the npm package on every release

- **Central Server** (`server/`)
  Rust backend (Axum or Actix-Web)  
  - Aggregates alerts & decisions from agents  
  - Maintains local threat database (PostgreSQL / SQLite)  
  - Analyzes patterns, computes reputation scores  
  - Distributes global/local block decisions  
  - Secure API (TLS, JWT auth)

- **Dashboard** (`dashboard/`)
  Modern web UI built with Next.js  
  - Monitor agents, view alerts, edit rules  
  - Real-time updates (WebSockets / SSE)  
  - Visualizations: attack timelines, geo-maps, top attackers  
  - Rule editor (YAML-like scenarios)  
  - Fully self-hostable via Docker Compose (or Vercel)

- **Threat Intelligence**
  Start with high-quality free community feeds (no CrowdSec hub required):
  - **IPsum** (stamparm/ipsum) — daily aggregated feed with hit scores  
    → https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt (filter ≥ 3–5)
  - **FireHOL level1 / level2** — curated safe blocklists  
    → https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
  - **DigitalSide Threat-Intel** — malware-related IPs in CSV  
    → https://osint.digitalside.it/Threat-Intel/csv/
  - Others: LGOG Flagged_IP_List, sefinek Malicious-IP-Addresses, Abuse.ch trackers

  Automatic daily ingestion is handled by the central server.

## Repo Structure
```
bannkenn/                          # github.com/OpenTech-Lab/bannkenn
├── dashboard/                     # Next.js frontend + dashboard UI
├── agent/                         # Rust agent source (native core)
├── server/                        # Rust central server + API
├── docker/                        # Dockerfiles & docker-compose.yml
├── scripts/                       # Build & release scripts
├── .github/
│   └── workflows/                 # CI/CD (Rust tests, Docker builds, npm publish)
├── README.md
├── .gitignore
└── LICENSE
```

## Key Technologies
| Component      | Technology                          | Why? |
|----------------|-------------------------------------|------|
| Agent & Server | Rust (tokio, axum/actix-web, sqlx)  | Safety, speed, no memory bugs |
| Dashboard      | Next.js 16+ (App Router)            | Modern UI, SSR, easy API integration |
| Database       | PostgreSQL (or SQLite)              | Reliable storage for alerts/threats |
| Agent Install  | npm + GitHub Actions                | Easy global installation |
| Deployment     | Docker Compose / Kubernetes         | Simple self-hosting & scaling |

## Installation

### 1. Self-Host Server + Dashboard (Recommended)

```bash
git clone https://github.com/OpenTech-Lab/bannkenn.git
cd bannkenn

# Start everything with one command
docker compose up -d
```

Dashboard will be available at `http://localhost:3021` (or your domain).

### 2. Install Agent via npm

```bash
npm install -g bannkenn-agent

# Initialize and register with your server
bannkenn-agent init
```

The npm package automatically downloads the correct native Rust binary for your platform (Linux, macOS, Windows, arm64/x64).

## Getting Started (Planned MVP Roadmap)
1. Rust agent prototype + npm packaging
2. Simple central server + PostgreSQL
3. Import community IP lists (cron job)
4. Next.js dashboard skeleton + auth
5. Agent ↔ Server communication (REST/gRPC + TLS)
6. Firewall bouncer integration
7. Visualizations & rule editor

## Why Build This?
- CrowdSec is great but ties you to their ecosystem.
- Rust reduces attack surface vs Go.
- Full data sovereignty — everything stays on-prem.
- Easy agent deployment via the familiar `npm` command.
