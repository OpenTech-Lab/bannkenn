# BannKenn Operations and Containment Runbook

This runbook covers the operational gaps that matter for production rollouts:

- rolling the server or agent back to a known release
- validating eBPF, cgroup, and `tc` containment prerequisites on a real Linux host

## Rollback

### Server and dashboard rollback

The server/dashboard update flow is Git-driven, so the safest rollback is to move the repo back to a known tag and re-run the existing update helper.

1. Back up the data directory before crossing releases:

```bash
sudo cp /data/bannkenn.db /data/bannkenn.db.bak
```

2. Check out the target release tag:

```bash
git fetch --tags
git checkout v1.4.5
```

3. Re-apply the stack with the existing mode-preserving update wrapper:

```bash
sudo bash scripts/update-server.sh
```

4. Verify the API and dashboard health endpoints:

```bash
curl http://127.0.0.1:3022/api/v1/health
curl http://127.0.0.1:3021/api/health
```

If you run the native-TLS deployment mode, `scripts/update-server.sh` will preserve the existing certificate paths and refuse TLS-regeneration flags during the rollback.

### Agent rollback

If the agent is already installed, use the built-in updater so the Linux binary and its matching containment object stay aligned:

```bash
sudo bannkenn-agent update v1.4.5
```

On Linux, `bannkenn-agent update` installs both:

- the requested `bannkenn-agent` release binary
- the matching `bannkenn-containment-*.bpf.o` release asset into the default containment object path

`bannkenn-agent init` also checks for the Linux containment object and installs the matching release asset automatically if it is missing.
If the binary is already up to date but the containment object is missing, `sudo bannkenn-agent update` repairs the missing `.bpf.o` and restarts the service when it had to install the asset.

If you are doing a manual release install instead of using the updater, install both files together:

```bash
curl -Lo bannkenn-agent \
  https://github.com/OpenTech-Lab/bannkenn/releases/download/v1.4.5/bannkenn-agent-linux-x64
curl -Lo bannkenn-containment.bpf.o \
  https://github.com/OpenTech-Lab/bannkenn/releases/download/v1.4.5/bannkenn-containment-linux-x64.bpf.o

sudo install -m 755 bannkenn-agent /usr/local/bin/bannkenn-agent
sudo install -d /usr/lib/bannkenn/ebpf
sudo install -m 644 bannkenn-containment.bpf.o /usr/lib/bannkenn/ebpf/bannkenn-containment.bpf.o
sudo systemctl restart bannkenn-agent
```

## Real-host containment prerequisites

### eBPF attachment

The current agent runtime expects all of the following:

- Linux `5.8+`
- the containment object at one of:
  - `agent/ebpf/bannkenn-containment.bpf.o`
  - `/usr/lib/bannkenn/ebpf/bannkenn-containment.bpf.o`
  - `/usr/local/lib/bannkenn/ebpf/bannkenn-containment.bpf.o`
- containment enabled in `~/.config/bannkenn/agent.toml`
- at least one configured `watch_paths` entry
- privileges sufficient to load and attach tracepoint programs

For a root-owned systemd service, the default service unit already runs as `root`, which is the intended deployment mode. If you run the agent in a container or under a restricted launcher, eBPF tracepoint loading typically requires:

- `CAP_BPF` and `CAP_PERFMON` on newer kernels
- or `CAP_SYS_ADMIN` on older kernels that still gate BPF operations there

On a real host, the success signal is now explicit in the journal:

- success: `Containment Aya backend initialized from ...`
- fallback: `Failed to initialize Aya backend ...; falling back to userspace polling`

### cgroup I/O throttling

The cgroup enforcer writes under `/sys/fs/cgroup`, so the host must provide:

- unified cgroups v2 mounted at `/sys/fs/cgroup`
- the `io` controller listed in `cgroup.controllers`
- permission to enable `+io` in `cgroup.subtree_control`
- permission to create `/sys/fs/cgroup/bannkenn/...`
- permission to write `io.max` and `cgroup.procs`

When enforcement is active and `dry_run = false`, success/failure shows up in agent logs as:

- `applied cgroup I/O throttle ...`
- `cgroup I/O throttle failed: ...`

### Network throttling with `tc`

The traffic-control enforcer expects:

- the `tc` binary to be present
- permission to inspect `/proc/net/route`
- permission to replace qdiscs, classes, and filters on the selected network interface
- `CAP_NET_ADMIN` when the agent is not running with full root privileges

If `containment.throttle_network_interface` is unset, the agent derives the default interface from `/proc/net/route`.

When enforcement is active and `dry_run = false`, success/failure shows up in agent logs as:

- `applied network throttle on ...`
- `network throttle failed: ...`

## Live-host validation workflow

1. Enable containment in `~/.config/bannkenn/agent.toml`.

At minimum, set:

```toml
[containment]
enabled = true
dry_run = true
throttle_enabled = true
fuse_enabled = false
watch_paths = ["/srv/data"]
protected_paths = ["/srv/data"]
```

2. Restart the service:

```bash
sudo systemctl restart bannkenn-agent
```

3. Inspect the recent journal:

```bash
sudo journalctl -u bannkenn-agent -n 200 --no-pager
```

4. Collect the full diagnostics bundle:

```bash
sudo bash scripts/collect-containment-diagnostics.sh
```

5. If eBPF is attaching cleanly, switch from `dry_run = true` to `dry_run = false` only on a host where you are prepared to test throttling.

6. Re-run the diagnostics bundle and look for:

- `Containment Aya backend initialized from ...`
- `applied cgroup I/O throttle ...`
- `applied network throttle on ...`

If you want me to confirm the last two unchecked TODO items against a real host, send back the output of `scripts/collect-containment-diagnostics.sh` and the latest `journalctl -u bannkenn-agent -n 200 --no-pager` from one of the deployed servers.
