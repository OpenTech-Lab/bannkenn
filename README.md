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

### 2. Configure local setup values

Before running `scripts/install.sh` or `scripts/generate-ip-cert.sh`, copy the local env template and replace the placeholders with your own IP/hostname and TLS settings:

```bash
cp .env.example .env
$EDITOR .env
```

At minimum, set `BANNKENN_PUBLIC_ADDRESS`. For self-signed TLS flows, also set `BANNKENN_TLS_SANS` to every IP/hostname agents or browsers will use.

### 3. Start server + dashboard

Recommended one-command HTTP setup:

```bash
sudo bash scripts/install.sh dashboard
```

Manual equivalent:

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

### Recommended: native TLS on the Rust API server

If your dashboard stays local and only agents need secure remote access, native TLS in `bannkenn-server` is the cleanest setup:
- public/native TLS API: `https://SERVER_IP:3022`
- local dashboard UI: `http://SERVER_IP:3021`
- optional local-only plain API for the dashboard: `http://127.0.0.1:3023`

1. Generate a certificate whose SAN entries match every address agents will use.

If you want the helper to generate a self-signed certificate for you, skip this manual step and pass one or more `--tls-san` values to `dashboard-native-tls`.

If `.env` already contains `BANNKENN_TLS_SANS` and `BANNKENN_TLS_DIR`, the helper can use them directly:

```bash
sudo bash scripts/generate-ip-cert.sh
```

Override examples:

```bash
sudo bash scripts/generate-ip-cert.sh --out-dir /etc/bannkenn/tls 192.0.2.10
sudo bash scripts/generate-ip-cert.sh --out-dir /etc/bannkenn/tls 192.0.2.10 198.51.100.24
```

2. Start Docker Compose with native TLS enabled on the API and a loopback-only plain port for the local dashboard.

Recommended one-command flow after generating the certs:

If you generated the certs in `/etc/bannkenn/tls`:

```bash
sudo bash scripts/install.sh dashboard-native-tls
```

If the certs do not exist yet and agents will connect to `123.123.123.123`:

```bash
sudo bash scripts/install.sh dashboard-native-tls --tls-san 123.123.123.123
```

If you generated the certs in `/etc/nginx/ssl`:

```bash
sudo bash scripts/install.sh dashboard-native-tls --tls-dir /etc/nginx/ssl
```

That helper now auto-generates `bannkenn.crt` and `bannkenn.key` when they are missing, using either the provided `--tls-san` values or auto-detected local IP/hostnames. `server-native-tls` remains available as a backward-compatible alias.

Manual equivalent if you prefer to run Compose yourself:

```bash
export BANNKENN_SERVER_TLS_DIR=/etc/bannkenn/tls
export BANNKENN_TLS_CERT_PATH=/etc/bannkenn/tls/bannkenn.crt
export BANNKENN_TLS_KEY_PATH=/etc/bannkenn/tls/bannkenn.key
export BANNKENN_LOCAL_BIND=127.0.0.1:3023
export BANNKENN_DASHBOARD_SERVER_URL=http://127.0.0.1:3023
docker compose -f docker/docker-compose.yml up -d --build
```

If you already generated the certificate under `/etc/nginx/ssl`, the manual equivalent is:

```bash
export BANNKENN_SERVER_TLS_DIR=/etc/nginx/ssl
export BANNKENN_TLS_CERT_PATH=/etc/bannkenn/tls/bannkenn.crt
export BANNKENN_TLS_KEY_PATH=/etc/bannkenn/tls/bannkenn.key
```

`BANNKENN_SERVER_TLS_DIR` is the host-side directory mounted into the server container. `BANNKENN_TLS_CERT_PATH` and `BANNKENN_TLS_KEY_PATH` are the in-container paths.

3. Use these endpoints:
- dashboard UI: `http://192.0.2.10:3021`
- public API health: `https://192.0.2.10:3022/api/v1/health`
- local dashboard-to-API path: `http://127.0.0.1:3023`

Open these ports on your server for this layout:
- `3022` if remote agents need the API over TLS
- `3021` only if you want to open the dashboard UI from another machine on your LAN

Keep `3023` local only. It exists so the local dashboard and the container healthcheck do not need to trust the self-signed API certificate.

Set the agent `server_url` to the native TLS API address:

```bash
https://192.0.2.10:3022
```

### Optional: HTTPS via Docker Compose nginx

The main compose file also includes an optional `nginx` service behind the `tls` profile. Use this only if you still want reverse-proxy TLS, or if you later decide to expose the dashboard over HTTPS too.

This nginx container uses host networking so it can proxy to:
- server API: `127.0.0.1:3022`
- dashboard UI: `127.0.0.1:3021`

Important: nginx is not started by the plain `docker compose up -d --build` command above. If you want this path, you must both generate the certificate and start the `tls` profile.

Because the server and dashboard already bind host `3022` and `3021`, nginx cannot also listen on those same ports. This means the following is **not** valid:
- `https://SERVER_IP:3022` -> nginx -> `127.0.0.1:3022`
- `https://SERVER_IP:3021` -> nginx -> `127.0.0.1:3021`

Without a domain name, do **not** proxy both services behind one public IP/port with a shared `/api/` split, because the Next.js dashboard already uses its own `/api/*` routes.

Recommended nginx layout for the current repo state:
- `https://SERVER_IP:1234` -> BannKenn server API on `127.0.0.1:3022`
- `https://SERVER_IP:1235` -> BannKenn dashboard on `127.0.0.1:3021`

1. Generate a certificate whose SAN entries match the exact address clients will use.

```bash
sudo bash scripts/generate-ip-cert.sh --out-dir /etc/nginx/ssl
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

If you use self-signed certificates or a private CA, the agent and browser must trust that CA/certificate.

For BannKenn agents, the easiest self-signed path is now trust-on-first-use:
- leave `ca_cert_path` blank
- run `sudo bannkenn-agent connect`
- review the SHA-256 fingerprint shown by the agent
- answer `y` to pin that certificate locally for future connections

The pinned certificate is stored under `~/.config/bannkenn/certs/`.

If you do not want to modify the whole system trust store on the agent machine, BannKenn agent can now trust a specific PEM file via `ca_cert_path` in `~/.config/bannkenn/agent.toml`.

Example:

```toml
server_url = "https://123.123.123.123:3022"
ca_cert_path = "/etc/bannkenn/server-ca.pem"
```

Copy the PEM certificate from the server to that path on the agent machine before running `bannkenn-agent connect`.

Important: the address in `server_url` must be present in the certificate SAN list. For example, if the certificate was generated for a different IP or hostname than `123.123.123.123`, TLS verification will fail because the address does not match.

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

`init` now auto-detects available log sources, auto-selects a log file path, writes `/etc/systemd/system/bannkenn-agent.service` automatically on Linux/systemd when run with `sudo`, and attempts server registration immediately.

When the server URL uses `https://`, `init` also prompts for an optional custom CA/cert PEM path. Leave it blank to use the normal system trust store or the trust-on-first-use flow during `connect`.

Enter the API URL here, not the dashboard URL:
- native TLS example: `https://192.0.2.10:3022`
- nginx/TLS example: `https://192.0.2.10:1234`
- wrong: `https://192.0.2.10:1235`

If the BannKenn server was unreachable during `init`, retry registration later with:

```bash
sudo bannkenn-agent connect
```

`connect` now only refreshes/saves the JWT token. It does not start the foreground agent loop.

If `connect` fails with `UnknownIssuer`, either:
- install the server certificate/CA into the system trust store on the agent machine
- or copy the PEM file locally and set `ca_cert_path` in `~/.config/bannkenn/agent.toml`

If `connect` reaches a self-signed HTTPS server and no `ca_cert_path` is configured, BannKenn now offers to:
- download the presented certificate
- show its SHA-256 fingerprint
- save it locally under `~/.config/bannkenn/certs/`
- retry registration using that pinned certificate

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
