# BannKenn – Self-Hosted Collaborative Intrusion Prevention System

![Bannkenn](docs/images/Bannkenn.png)

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
docker compose -f docker/docker-compose.yml up -d --build
```

Check health:

```bash
curl http://localhost:3022/api/v1/health
```

Open dashboard:
- `http://localhost:3021`

### 3. Install agent binary (choose one)

Option A: build from source (Linux/systemd path)

```bash
# from the cloned repo root
sudo bash scripts/install.sh
```

This installs:
- binary: `/usr/local/bin/bannkenn-agent`
- service binary only; `bannkenn-agent init` installs `bannkenn-agent.service`

Option B: install from GitHub Release URL (Linux x64 example)

```bash
VERSION=v1.0.0
curl -fL "https://github.com/OpenTech-Lab/bannkenn/releases/download/${VERSION}/bannkenn-agent-linux-x64" -o bannkenn-agent
chmod +x bannkenn-agent
sudo mv bannkenn-agent /usr/local/bin/bannkenn-agent
```

Update an installed agent:

```bash
sudo bannkenn-agent update
sudo bannkenn-agent update v1.3.18
```

`update` downloads the correct release asset for the current platform, replaces the installed binary, and restarts `bannkenn-agent` automatically when the systemd service is active.

Linux ARM64:

```bash
VERSION=v1.0.0
curl -fL "https://github.com/OpenTech-Lab/bannkenn/releases/download/${VERSION}/bannkenn-agent-linux-arm64" -o bannkenn-agent
chmod +x bannkenn-agent
sudo mv bannkenn-agent /usr/local/bin/bannkenn-agent
```

Windows PowerShell:

```powershell
$version = "v1.0.0"
Invoke-WebRequest -Uri "https://github.com/OpenTech-Lab/bannkenn/releases/download/$version/bannkenn-agent-windows-x64.exe" -OutFile "bannkenn-agent.exe"
```

### 4. Initialize agent configuration

```bash
sudo bannkenn-agent init
```

`init` now auto-detects available log sources, auto-selects a log file path, writes `/etc/systemd/system/bannkenn-agent.service` automatically on Linux/systemd when run with `sudo`, and attempts dashboard registration immediately.

If the dashboard server was unreachable during `init`, retry registration later with:

```bash
sudo bannkenn-agent connect
```

`connect` now only refreshes/saves the JWT token. It does not start the foreground agent loop.

### 5. Start the systemd service

```bash
sudo systemctl enable --now bannkenn-agent
```

```bash
sudo systemctl status bannkenn-agent
sudo systemctl restart bannkenn-agent
```

Stopping the service removes BannKenn-managed nftables rules, including its dedicated nftables table and blocklist set.

### 6. Verify agent status

```bash
sudo systemctl status bannkenn-agent --no-pager
sudo journalctl -u bannkenn-agent -n 100 --no-pager
```

The dashboard agent status is `online` when heartbeat updates are received within 2 minutes.

## Common Operations

### Install

Server + dashboard:

```bash
git clone https://github.com/OpenTech-Lab/bannkenn.git
cd bannkenn
docker compose -f docker/docker-compose.yml up -d --build
```

Agent from source:

```bash
cd bannkenn
sudo bash scripts/install.sh
sudo bannkenn-agent init
sudo systemctl enable --now bannkenn-agent
```

If `init` could not reach the server yet:

```bash
sudo bannkenn-agent connect
sudo systemctl restart bannkenn-agent
```

### Stop

Stop server + dashboard:

```bash
docker compose -f docker/docker-compose.yml down
```

Stop only the agent service:

```bash
sudo systemctl stop bannkenn-agent
```

This stop path also removes BannKenn-managed nftables rules via `ExecStopPost`.

### Update

Update the installed agent to the latest release:

```bash
sudo bannkenn-agent update
```

Update to a specific release:

```bash
sudo bannkenn-agent update v1.3.18
```

The updater replaces `/usr/local/bin/bannkenn-agent` and restarts `bannkenn-agent` automatically when the systemd service is active.

To refresh the server/dashboard containers after pulling new code:

```bash
git pull
docker compose -f docker/docker-compose.yml up -d --build
```

### Reset Firewall

```bash
sudo bannkenn-agent cleanup-firewall
```

### Uninstall

Remove the agent from a Linux systemd host:

```bash
sudo bannkenn-agent uninstall
```

This stops/disables the service, removes `/etc/systemd/system/bannkenn-agent.service`, cleans up BannKenn-managed firewall state, deletes local agent config/JWT, and removes the running `bannkenn-agent` binary.

Remove the local server/dashboard stack and named volumes:

```bash
docker compose -f docker/docker-compose.yml down -v
```

If you also want to remove the checked-out source tree, delete the `bannkenn/` directory afterwards.

## Typical First-Troubleshooting Checks

- Agent shows `offline`:
  - run `sudo bannkenn-agent connect` again to refresh token
  - restart service so it picks up the new token: `sudo systemctl restart bannkenn-agent`
  - inspect logs for `heartbeat error 401`
- Service fails to start:
  - confirm `/root/.config/bannkenn/agent.toml` exists
  - confirm `server_url` points to reachable server
  - check `journalctl` output for exact error text

## License
MIT
