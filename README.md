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

This starts only the HTTP services:
- API: `http://SERVER_IP:3022`
- dashboard: `http://SERVER_IP:3021`

### Optional: HTTPS via Docker Compose nginx

The main compose file now includes an optional `nginx` service behind the `tls` profile. This nginx container uses host networking so it can proxy to:
- server API: `127.0.0.1:3022`
- dashboard UI: `127.0.0.1:3021`

Important: nginx is not started by the plain `docker compose up -d --build` command above. If you want HTTPS, you must both generate the certificate and start the `tls` profile.

Because the server and dashboard already bind host `3022` and `3021`, nginx cannot also listen on those same ports. This means the following is **not** valid:
- `https://SERVER_IP:3022` -> nginx -> `127.0.0.1:3022`
- `https://SERVER_IP:3021` -> nginx -> `127.0.0.1:3021`

Without a domain name, do **not** proxy both services behind one public IP/port with a shared `/api/` split, because the Next.js dashboard already uses its own `/api/*` routes.

Recommended layout for the current repo state:
- `https://SERVER_IP:1234` -> BannKenn server API on `127.0.0.1:3022`
- `https://SERVER_IP:1235` -> BannKenn dashboard on `127.0.0.1:3021`

1. Generate a certificate whose SAN entries match the exact address clients will use.

If clients connect with the LAN IP only:

```bash
sudo bash deploy/nginx/generate-ip-cert.sh 192.0.2.10 /etc/nginx/ssl
```

If some clients connect with the LAN IP and others use the public IP, include both:

```bash
sudo bash deploy/nginx/generate-ip-cert.sh --out-dir /etc/nginx/ssl 192.0.2.10 198.51.100.24
```

2. Start BannKenn with the TLS profile:

```bash
docker compose -f docker/docker-compose.yml --profile tls up -d --build
```

3. Open the TLS endpoints:
- dashboard: `https://192.0.2.10:1235`
- API health: `https://192.0.2.10:1234/api/v1/health`

If you want to store the generated certs somewhere else, set `BANNKENN_NGINX_SSL_DIR` before starting compose:

```bash
export BANNKENN_NGINX_SSL_DIR=/path/to/your/nginx-ssl
docker compose -f docker/docker-compose.yml --profile tls up -d --build
```

If you terminate TLS in nginx, set the agent `server_url` to the API IP+port:

```bash
https://192.0.2.10:1234
```

If you still want public `3022` and `3021`, you must first move the backend services to different internal ports so nginx can own the public ports, for example:
- backend server bind: `127.0.0.1:4022`
- backend dashboard bind: `127.0.0.1:4021`
- nginx public API: `https://SERVER_IP:3022` -> `127.0.0.1:4022`
- nginx public dashboard: `https://SERVER_IP:3021` -> `127.0.0.1:4021`

In that alternate layout the agent `server_url` would be:

```bash
https://192.0.2.10:3022
```

If you use self-signed certificates or a private CA, the agent and browser must trust that CA/certificate.

If you do not want to modify the whole system trust store on the agent machine, BannKenn agent can now trust a specific PEM file via `ca_cert_path` in `~/.config/bannkenn/agent.toml`.

Example:

```toml
server_url = "https://221.103.201.166:1234"
ca_cert_path = "/etc/bannkenn/server-ca.pem"
```

Copy the PEM certificate from the server to that path on the agent machine before running `bannkenn-agent connect`.

Important: the address in `server_url` must be present in the certificate SAN list. For example, if the certificate was generated for `192.168.11.9` but the agent connects to `https://221.103.201.166:1234`, TLS verification will fail because the IPs do not match.

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
You do not need to run `systemctl restart bannkenn-agent` manually after `sudo bannkenn-agent update` unless the service was inactive when you ran the updater.

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

When the server URL uses `https://`, `init` also prompts for an optional custom CA/cert PEM path. Leave it blank to use the normal system trust store.

If you put nginx/TLS in front of BannKenn, enter the API URL here, not the dashboard URL:
- correct: `https://192.0.2.10:1234`
- wrong: `https://192.0.2.10:1235`

If the dashboard server was unreachable during `init`, retry registration later with:

```bash
sudo bannkenn-agent connect
```

`connect` now only refreshes/saves the JWT token. It does not start the foreground agent loop.

If `connect` fails with `UnknownIssuer`, either:
- install the server certificate/CA into the system trust store on the agent machine
- or copy the PEM file locally and set `ca_cert_path` in `~/.config/bannkenn/agent.toml`

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
If the service was already active, no extra manual restart step is required after `sudo bannkenn-agent update`.
If the updater reports that `bannkenn-agent` did not stay active after restart, inspect `sudo systemctl status bannkenn-agent --no-pager` and `sudo journalctl -u bannkenn-agent -n 100 --no-pager`.

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
