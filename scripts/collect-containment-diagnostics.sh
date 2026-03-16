#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="bannkenn-agent"
SERVICE_HOME="/root"
CONFIG_DIR="${XDG_CONFIG_HOME:-$SERVICE_HOME/.config}/bannkenn"
AGENT_CONFIG_PATH="${BANNKENN_AGENT_CONFIG_PATH:-$CONFIG_DIR/agent.toml}"
DEFAULT_EBPF_PATHS=(
  "/usr/lib/bannkenn/ebpf/bannkenn-containment.bpf.o"
  "/usr/local/lib/bannkenn/ebpf/bannkenn-containment.bpf.o"
)

print_section() {
  printf '\n== %s ==\n' "$1"
}

run_cmd() {
  printf '$'
  for arg in "$@"; do
    printf ' %q' "$arg"
  done
  printf '\n'
  "$@" 2>&1 || true
}

print_file_if_present() {
  local path="$1"
  if [[ -e "$path" ]]; then
    run_cmd ls -l "$path"
  else
    printf 'missing: %s\n' "$path"
  fi
}

main_pid() {
  systemctl show "$SERVICE_NAME" --property MainPID --value 2>/dev/null || true
}

print_section "Host"
run_cmd date -Is
run_cmd uname -a
run_cmd id

print_section "Agent binary and version"
run_cmd command -v bannkenn-agent
run_cmd bannkenn-agent --version

print_section "Containment configuration"
print_file_if_present "$AGENT_CONFIG_PATH"
if [[ -f "$AGENT_CONFIG_PATH" ]]; then
  awk '
    /^\[containment\]/ { in_block=1 }
    /^\[/ && $0 != "[containment]" && in_block { exit }
    in_block { print }
  ' "$AGENT_CONFIG_PATH"
fi

print_section "Installed containment BPF objects"
if [[ -n "${BANNKENN_EBPF_INSTALL_DIR:-}" ]]; then
  print_file_if_present "${BANNKENN_EBPF_INSTALL_DIR%/}/bannkenn-containment.bpf.o"
fi
for path in "${DEFAULT_EBPF_PATHS[@]}"; do
  print_file_if_present "$path"
done

print_section "Service state"
run_cmd systemctl show "$SERVICE_NAME" --property ActiveState,SubState,MainPID,ExecMainStatus
run_cmd systemctl status --no-pager --full "$SERVICE_NAME"

pid="$(main_pid)"
if [[ "$pid" =~ ^[0-9]+$ ]] && (( pid > 0 )) && [[ -r "/proc/$pid/status" ]]; then
  print_section "Process capabilities"
  run_cmd grep -E '^(Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs):' "/proc/$pid/status"
  if command -v capsh >/dev/null 2>&1; then
    cap_eff="$(awk '/^CapEff:/ { print $2 }' "/proc/$pid/status")"
    if [[ -n "$cap_eff" ]]; then
      run_cmd capsh --decode="$cap_eff"
    fi
  fi
fi

print_section "Kernel and cgroup prerequisites"
run_cmd uname -r
run_cmd mount
run_cmd cat /sys/fs/cgroup/cgroup.controllers
run_cmd cat /sys/fs/cgroup/cgroup.subtree_control
run_cmd ls -ld /sys/fs/cgroup /sys/fs/cgroup/bannkenn

print_section "Network throttling prerequisites"
run_cmd cat /proc/net/route
run_cmd command -v tc
if command -v tc >/dev/null 2>&1; then
  run_cmd tc qdisc show
fi

print_section "Optional BPF visibility"
run_cmd command -v bpftool
if command -v bpftool >/dev/null 2>&1; then
  run_cmd bpftool prog show
  run_cmd bpftool link show
fi

print_section "Recent agent logs"
run_cmd journalctl -u "$SERVICE_NAME" -n 200 --no-pager

print_section "Containment-specific log excerpts"
journalctl -u "$SERVICE_NAME" -n 200 --no-pager 2>/dev/null \
  | grep -E 'Containment|Aya|userspace polling|failed to initialize|failed to attach|cgroup|network throttle' \
  || true
