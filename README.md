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
docker compose up -d
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
# download this repo
git clone https://github.com/OpenTech-Lab/bannkenn

# run installer
sudo bash install.sh

```

This installs:
- binary: `/usr/local/bin/bannkenn-agent`
- service: `bannkenn-agent.service` (enabled)

Option B: install from GitHub Release URL (Linux x64 example)

```bash
VERSION=v1.0.0
curl -fL "https://github.com/OpenTech-Lab/bannkenn/releases/download/${VERSION}/bannkenn-agent-linux-x64" -o bannkenn-agent
chmod +x bannkenn-agent
sudo mv bannkenn-agent /usr/local/bin/bannkenn-agent
```

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

`init` now auto-detects available log sources and auto-selects a log file path.

### 5. Register the agent to get JWT token

```bash
sudo bannkenn-agent connect
```

Note: current `connect` command also starts the agent foreground loop after registration.  
After registration succeeds, press `Ctrl+C` to return to shell.

### 6. Start the systemd service

`sudo nano /etc/systemd/system/bannkenn-agent.service`
```yml
[Unit]
Description=BannKenn IPS Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/bannkenn-agent
Restart=on-failure
RestartSec=5
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now bannkenn-agent
```

```bash
sudo systemctl status bannkenn-agent
sudo systemctl restart bannkenn-agent
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
