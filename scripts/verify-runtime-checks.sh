#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_PATH="${BIN_PATH:-$ROOT_DIR/target/debug/bannkenn-agent}"
TMP_DIR="$(mktemp -d /tmp/bannkenn-runtime-verify.XXXXXX)"
HOME_DIR="$TMP_DIR/home"
CONFIG_DIR="$HOME_DIR/.config/bannkenn"
LOG_PATH="$TMP_DIR/auth.log"
JOURNALD_OUT="$TMP_DIR/journald.out"
NORMAL_OUT="$TMP_DIR/normal.out"
STORM_OUT="$TMP_DIR/storm.out"
CPU_HZ="$(getconf CLK_TCK)"

cleanup() {
    if [[ -n "${AGENT_PID:-}" ]]; then
        kill -INT "$AGENT_PID" 2>/dev/null || true
        sleep 1
        if kill -0 "$AGENT_PID" 2>/dev/null; then
            kill -KILL "$AGENT_PID" 2>/dev/null || true
        fi
        wait "$AGENT_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT

mkdir -p "$CONFIG_DIR"
: >"$LOG_PATH"

write_config() {
    local log_paths_literal="$1"
    cat >"$CONFIG_DIR/agent.toml" <<EOF
server_url = "http://127.0.0.1:9"
jwt_token = "verification-token"
agent_name = "verification-agent"
uuid = "00000000-0000-0000-0000-000000000001"
log_path = "$LOG_PATH"
log_paths = [$log_paths_literal]
threshold = 3
window_secs = 60

[containment]
enabled = false
dry_run = true
watch_paths = []
protected_paths = []
poll_interval_ms = 1000
EOF
}

start_agent() {
    local output_path="$1"
    env \
        HOME="$HOME_DIR" \
        XDG_CONFIG_HOME="$HOME_DIR/.config" \
        RUST_LOG=info \
        "$BIN_PATH" run >"$output_path" 2>&1 &
    AGENT_PID=$!
    sleep 2
}

stop_agent() {
    if [[ -n "${AGENT_PID:-}" ]]; then
        kill -INT "$AGENT_PID" 2>/dev/null || true
        sleep 1
        if kill -0 "$AGENT_PID" 2>/dev/null; then
            kill -KILL "$AGENT_PID" 2>/dev/null || true
        fi
        wait "$AGENT_PID" 2>/dev/null || true
        unset AGENT_PID
    fi
}

read_cpu_ticks() {
    local pid="$1"
    awk '{print $14 + $15}' "/proc/$pid/stat"
}

measure_cpu_pct() {
    local pid="$1"
    local duration_secs="$2"
    local start_ticks
    local end_ticks
    start_ticks="$(read_cpu_ticks "$pid")"
    sleep "$duration_secs"
    end_ticks="$(read_cpu_ticks "$pid")"
    awk \
        -v start="$start_ticks" \
        -v end="$end_ticks" \
        -v hz="$CPU_HZ" \
        -v duration="$duration_secs" \
        'BEGIN { printf "%.2f", ((end - start) / hz) / duration * 100 }'
}

run_journald_check() {
    write_config "\"$LOG_PATH\", \"/var/log/auth.log\""
    start_agent "$JOURNALD_OUT"
    sleep 3
    stop_agent

    if ! grep -q "Using journald auth stream journald:auth instead of legacy auth file polling" "$JOURNALD_OUT"; then
        echo "journald_check=failed"
        echo "journald_reason=missing_journald_startup_log"
        return 1
    fi

    if grep -q "Failed to open /var/log/auth.log" "$JOURNALD_OUT"; then
        echo "journald_check=failed"
        echo "journald_reason=legacy_auth_file_was_polled"
        return 1
    fi

    echo "journald_check=passed"
}

run_cpu_benchmarks() {
    write_config "\"$LOG_PATH\""
    : >"$LOG_PATH"
    start_agent "$NORMAL_OUT"
    local normal_cpu
    normal_cpu="$(measure_cpu_pct "$AGENT_PID" 5)"
    stop_agent

    : >"$LOG_PATH"
    start_agent "$STORM_OUT"
    (
        awk 'BEGIN {
            for (i = 0; i < 100000; i++) {
                print "Mar 20 00:00:00 host sshd[1]: Failed password for root from 198.51.100.10 port 22 ssh2"
            }
        }' >>"$LOG_PATH"
    ) &
    local writer_pid=$!
    local storm_cpu
    storm_cpu="$(measure_cpu_pct "$AGENT_PID" 5)"
    wait "$writer_pid"
    stop_agent

    echo "normal_cpu_pct=$normal_cpu"
    echo "storm_cpu_pct=$storm_cpu"
    echo "storm_lines=$(wc -l <"$LOG_PATH")"
}

(cd "$ROOT_DIR" && cargo build -p bannkenn-agent >/dev/null)

run_journald_check
run_cpu_benchmarks
