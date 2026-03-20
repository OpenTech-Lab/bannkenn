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
- Easy distribution: agent can be installed from GitHub Releases or built from source.

## Architecture (High Level)

- `agent/`: local watcher + detector + firewall enforcer
- `server/`: central API + persistence + aggregation logic
- `dashboard/`: Next.js web UI for health and decisions
- `docker/`: containerized local/prod-style deployment

## How to use

### Server/Dashboard
For `v1.4.6`, most users only need to set up `.env` and run the shell scripts under `scripts/`.

1. Clone the repo and create `.env`

```bash
git clone https://github.com/OpenTech-Lab/bannkenn.git
cd bannkenn
cp .env.example .env
$EDITOR .env
```

2. Choose your server mode in `.env`

- HTTP: set `BANNKENN_PUBLIC_ADDRESS` and `BANNKENN_DEPLOY_MODE=http`
- Native TLS: set `BANNKENN_PUBLIC_ADDRESS`, `BANNKENN_DEPLOY_MODE=native-tls`, and `BANNKENN_TLS_SANS`
- Recommended: `native-tls` for most deployments

3. Start server + dashboard

HTTP:

```bash
sudo bash scripts/install.sh dashboard
```

Native TLS:

```bash
sudo bash scripts/install.sh dashboard-native-tls
```

4. Update the server later

```bash
git pull
sudo bash scripts/update-server.sh
```


### Agent
1. Install the agent on each Linux host

Check version in release:
```bash
VERSION="v1.4.17"

curl -Lo bannkenn-agent https://github.com/OpenTech-Lab/bannkenn/releases/download/${VERSION}/bannkenn-agent-linux-x64
curl -Lo bannkenn-containment.bpf.o https://github.com/OpenTech-Lab/bannkenn/releases/download/${VERSION}/bannkenn-containment-linux-x64.bpf.o

sudo install -m 755 bannkenn-agent /usr/local/bin/bannkenn-agent
sudo install -d /usr/lib/bannkenn/ebpf
sudo install -m 644 bannkenn-containment.bpf.o /usr/lib/bannkenn/ebpf/bannkenn-containment.bpf.o
```

Or Download whole repo then:
```bash
sudo bash scripts/install.sh
sudo bannkenn-agent init
sudo systemctl enable --now bannkenn-agent
```

On Linux, `bannkenn-agent init` now checks that the containment `.bpf.o` exists, installs the matching release asset automatically when it is missing, and interactively offers to enable containment in dry-run mode with your chosen `watch_paths`/`protected_paths`.

When `bannkenn-agent init` asks for the server URL, use the API URL:

- HTTP: `http://SERVER_IP:3022`
- Native TLS: `https://SERVER_IP:3022`
- **Same machine as server (native-TLS):** `https://localhost:3022`
  - CA cert path: `/etc/bannkenn/tls/bannkenn.crt`
  - The TLS certificate automatically includes `localhost` and `127.0.0.1` as SANs, so `localhost` works without any extra steps.

Useful checks:

```bash
# HTTP mode
curl http://localhost:3022/api/v1/health
# Native-TLS mode
curl -k https://localhost:3022/api/v1/health
sudo systemctl status bannkenn-agent --no-pager
```

2. Update the agent later

```bash
sudo bannkenn-agent update
```

On Linux, this now refreshes both the released agent binary and the matching containment BPF object. If the binary is already current but the containment object is missing, `sudo bannkenn-agent update` will repair the missing `.bpf.o` and restart the service when needed.

If you want to configure or revise containment paths during an upgrade, run:

```bash
sudo bannkenn-agent update --configure-containment
```

If you want to manage certificates yourself, use `scripts/generate-ip-cert.sh` before the native-TLS install. Otherwise, `scripts/install.sh dashboard-native-tls` can generate the cert files from `.env`.

## Behavior Detection Model

BannKenn’s filesystem detector scores activity across path sensitivity, process trust, write/rename/delete pressure, extension anomalies, rewrite unreadability or entropy jumps, directory spread, recurrence, and suspicious lineage. User-facing severity is intentionally separate from automatic containment:

- `observed`: visible activity that did not accumulate enough corroboration for escalation.
- `suspicious`: enough weighted evidence to merit review, but not enough correlated ransomware-style signals for disruptive response.
- `high_risk`: correlated multi-signal behavior that looks meaningfully ransomware-like, but still needs repeated corroboration before automatic throttle/fuse actions.
- `containment_candidate`: the strongest user-facing severity band; automatic throttle/fuse still stays behind the separate action-confidence gates.

Default Linux trust seeds and suppressions include common maintenance and self-noise paths so protected-path writes do not automatically look malicious:

- trusted system or package-managed maintenance for `apt`, `dpkg`, `unattended-upgrades`, `snapd`, `fwupd`, `systemd`, and related helpers
- package-manager temp activity and trusted maintenance windows
- BannKenn-managed state paths and `bannkenn-agent` internal work

The main operator tuning knobs live under `[containment]` in `agent.toml`:

- severity thresholds: `suspicious_score`, `throttle_score`, `fuse_score`
- correlation gates: `meaningful_rename_count`, `meaningful_write_count`, `high_risk_min_signals`, `containment_candidate_min_signals`
- weighting knobs: `protected_path_bonus`, `user_data_bonus`, `unknown_process_bonus`, `extension_anomaly_score`, `recurrence_score`, `directory_spread_score`
- profile tuning: `environment_profile = "conservative" | "balanced" | "aggressive"`
- action confidence: `auto_containment_requires_pid`, `containment_action_window_secs`, `throttle_action_min_events`, `fuse_action_min_events`

Agents also pull a shared server snapshot for two fleet-wide signals:

- cross-agent IP attack pressure via the existing shared-risk categories
- low-risk shared process baselines keyed by executable plus service unit, package name, and/or container image

Those fleet process baselines are only exported after they appear on multiple agents and have no `high_risk` or `containment_candidate` history, so they reduce false positives for consistent managed workloads without blindly trusting one noisy host.

### Path sample: 
```
/etc/passwd,/etc/shadow,/etc/sudoers,/etc/sudoers.d/,/etc/pam.d/,/root/.ssh/authorized_keys,/bin/,/sbin/,/usr/bin/,/usr/sbin/,/usr/local/bin/,/lib/modules/,/etc/systemd/system/,/usr/lib/systemd/system/,/etc/init.d/,/etc/crontab/,/etc/cron.d/,/etc/rc.local,/etc/ld.so.preload,/etc/profile.d/,/etc/bashrc,/etc/hosts,/tmp/,/var/tmp/,/dev/shm/
```

## GeoLite2 Databases(Server)

IP geolocation (country, city, ASN) requires three MaxMind GeoLite2 databases placed in `server/data/`.
These files are **not bundled** with the repository — you must download them separately.

1. Create a free account at <https://www.maxmind.com/en/geolite2/signup>
2. Generate a licence key under **My Account → GeoIP / GeoLite -> Download files**

```bash
mkdir -p server/data

GeoLite2-Country.mmdb > server/data/GeoLite2-Country.mmdb
GeoLite2-City.mmdb > server/data/GeoLite2-City.mmdb
GeoLite2-ASN.mmdb > server/data/GeoLite2-ASN.mmdb
```

Alternatively, use the official [geoipupdate](https://github.com/maxmind/geoipupdate) tool to keep them automatically up to date.

> GeoLite2 data is created by MaxMind and licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).
> See `server/data/LICENSE` for the full attribution notice.

## Review
### coderabbitai
```bash
@coderabbitai review
```

## License
MIT
