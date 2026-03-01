# BannKenn – Self-Hosted Collaborative Intrusion Prevention System

**BannKenn** is a modern, fully open-source, self-managed alternative to CrowdSec.

It is a behavior-based Intrusion Prevention System (IPS) with lightweight agents for servers/PCs, a central threat aggregation server, and a real-time web dashboard.

Built for privacy-focused users, homelabs, and small teams that want full control without relying on external SaaS consoles.

## Why Build This?

- Full data sovereignty: your logs, decisions, and blocklists stay on your infrastructure.
- Rust-based agent and server: strong memory safety and high runtime performance.
- Self-host first: simple Docker deployment and no vendor lock-in.
- Practical operations: dashboard visibility plus host-level enforcement through firewall integrations.
- Easy distribution: agent can be installed through npm or built from source.

## Architecture (High Level)

- `agent/`: local watcher + detector + firewall enforcer
- `server/`: central API + persistence + aggregation logic
- `dashboard/`: Next.js web UI for health and decisions
- `docker/`: containerized local/prod-style deployment

## Install and Run (Step by Step)

### 1. Clone the repository

```bash
git clone https://github.com/OpenTech-Lab/bannkenn.git
cd bannkenn
```

### 2. Start server + dashboard

```bash
docker compose up -d
```

Check health:

```bash
curl http://localhost:3022/api/v1/health
```

Open dashboard:
- `http://localhost:3021`

### 3. Build and install the agent binary (Linux/systemd path)

```bash
sudo bash scripts/install.sh
```

This installs:
- binary: `/usr/local/bin/bannkenn-agent`
- service: `bannkenn-agent.service` (enabled)

### 4. Initialize agent configuration

```bash
sudo bannkenn-agent init
```

`init` now auto-detects available log sources and auto-selects a log file path.

### 5. Register the agent to get JWT token

```bash
sudo bannkenn-agent connect
```

Note: current `connect` command also starts the agent foreground loop after registration.  
After registration succeeds, press `Ctrl+C` to return to shell.

### 6. Start the systemd service

```bash
sudo systemctl enable --now bannkenn-agent
```

### 7. Verify agent status

```bash
sudo systemctl status bannkenn-agent --no-pager
sudo journalctl -u bannkenn-agent -n 100 --no-pager
```

The dashboard agent status is `online` when heartbeat updates are received within 2 minutes.

## Typical First-Troubleshooting Checks

- Agent shows `offline`:
  - run `sudo bannkenn-agent connect` again to refresh token
  - restart service: `sudo systemctl restart bannkenn-agent`
  - inspect logs for `heartbeat error 401`
- Service fails to start:
  - confirm `/root/.config/bannkenn/agent.toml` exists
  - confirm `server_url` points to reachable server
  - check `journalctl` output for exact error text

## License
MIT
