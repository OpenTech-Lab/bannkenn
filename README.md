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

5. Install the agent on each Linux host

```bash
sudo bash scripts/install.sh
sudo bannkenn-agent init
sudo systemctl enable --now bannkenn-agent
```

On Linux, `bannkenn-agent init` now checks that the containment `.bpf.o` exists, installs the matching release asset automatically when it is missing, and interactively offers to enable containment in dry-run mode with your chosen `watch_paths`/`protected_paths`.

When `bannkenn-agent init` asks for the server URL, use the API URL:

- HTTP: `http://SERVER_IP:3022`
- Native TLS: `https://SERVER_IP:3022`

Useful checks:

```bash
curl http://localhost:3022/api/v1/health
sudo systemctl status bannkenn-agent --no-pager
```

6. Update the agent later

```bash
sudo bannkenn-agent update
```

On Linux, this now refreshes both the released agent binary and the matching containment BPF object. If the binary is already current but the containment object is missing, `sudo bannkenn-agent update` will repair the missing `.bpf.o` and restart the service when needed.

If you want to configure or revise containment paths during an upgrade, run:

```bash
sudo bannkenn-agent update --configure-containment
```

If you want to manage certificates yourself, use `scripts/generate-ip-cert.sh` before the native-TLS install. Otherwise, `scripts/install.sh dashboard-native-tls` can generate the cert files from `.env`.

### Path sample: 
<pre>
/etc/passwd,/etc/shadow,/etc/sudoers,/etc/sudoers.d/,/etc/pam.d/,/root/.ssh/authorized_keys,/bin/,/sbin/,/usr/bin/,/usr/sbin/,/usr/local/bin/,/lib/modules/,/etc/systemd/system/,/usr/lib/systemd/system/,/etc/init.d/,/etc/crontab/,/etc/cron.d/,/etc/rc.local,/etc/ld.so.preload,/etc/profile.d/,/etc/bashrc,/etc/hosts,/tmp/,/var/tmp/,/dev/shm/
</pre>

## GeoLite2 Databases

IP geolocation (country, city, ASN) requires three MaxMind GeoLite2 databases placed in `server/data/`.
These files are **not bundled** with the repository — you must download them separately.

1. Create a free account at <https://www.maxmind.com/en/geolite2/signup>
2. Generate a licence key under **My Account → Manage Licence Keys**
3. Run the following commands from the repo root (replace `YOUR_LICENCE_KEY`):

```bash
mkdir -p server/data

curl -sL "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=YOUR_LICENCE_KEY&suffix=tar.gz" \
  | tar -xzO --wildcards "*/GeoLite2-Country.mmdb" > server/data/GeoLite2-Country.mmdb

curl -sL "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_LICENCE_KEY&suffix=tar.gz" \
  | tar -xzO --wildcards "*/GeoLite2-City.mmdb" > server/data/GeoLite2-City.mmdb

curl -sL "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=YOUR_LICENCE_KEY&suffix=tar.gz" \
  | tar -xzO --wildcards "*/GeoLite2-ASN.mmdb" > server/data/GeoLite2-ASN.mmdb
```

Alternatively, use the official [geoipupdate](https://github.com/maxmind/geoipupdate) tool to keep them automatically up to date.

> GeoLite2 data is created by MaxMind and licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).
> See `server/data/LICENSE` for the full attribution notice.

## License
MIT
