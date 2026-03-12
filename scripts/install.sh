#!/usr/bin/env bash
# BannKenn installer and dashboard/server compose helpers
# Usage:
#   sudo bash scripts/install.sh
#   sudo bash scripts/install.sh dashboard
#   sudo bash scripts/install.sh dashboard-native-tls [--tls-dir /etc/bannkenn/tls]

set -euo pipefail

BINARY_NAME="bannkenn-agent"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/root/.config/bannkenn"
VERSION="${BANNKENN_VERSION:-latest}"
DEFAULT_TLS_DIR="/etc/bannkenn/tls"
DEFAULT_LOCAL_BIND="127.0.0.1:3023"
DEFAULT_HTTP_DASHBOARD_URL="http://127.0.0.1:3022"
DEFAULT_TLS_DASHBOARD_URL="http://127.0.0.1:3023"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage:
  sudo bash scripts/install.sh
      Build and install bannkenn-agent from source.

  sudo bash scripts/install.sh agent
      Same as the default agent installation flow.

  sudo bash scripts/install.sh dashboard [options]
      Start the Docker Compose server/dashboard stack in plain HTTP mode.

  sudo bash scripts/install.sh dashboard-native-tls [options]
      Start the Docker Compose server/dashboard stack with native TLS on :3022
      and a loopback-only plain API listener for the dashboard on :3023.

  sudo bash scripts/install.sh server-native-tls [options]
      Backward-compatible alias for dashboard-native-tls.

Options for dashboard:
  --dashboard-url URL   Dashboard upstream URL
                        Default: http://127.0.0.1:3022
  --no-build            Skip docker compose --build
  -h, --help            Show this help

Options for dashboard-native-tls:
  --tls-dir DIR         Host directory containing bannkenn.crt and bannkenn.key
                        Default: /etc/bannkenn/tls
  --tls-san VALUE       Add an IP/hostname SAN when auto-generating a self-signed
                        certificate. Repeat to add multiple SANs.
  --local-bind ADDR     Loopback/plain API bind for dashboard health and local use
                        Default: 127.0.0.1:3023
  --dashboard-url URL   Dashboard upstream URL
                        Default: http://127.0.0.1:3023
  --regenerate-cert     Replace an existing bannkenn.crt/bannkenn.key pair
  --no-build            Skip docker compose --build
  -h, --help            Show this help
EOF
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This installer requires root privileges. Please run with sudo."
    fi
}

detect_arch() {
    local arch
    arch=$(uname -m)
    case $arch in
        x86_64)  echo "x86_64-unknown-linux-gnu" ;;
        aarch64) echo "aarch64-unknown-linux-gnu" ;;
        *)        error "Unsupported architecture: $arch" ;;
    esac
}

detect_firewall() {
    if command -v nft &>/dev/null; then
        echo "nftables"
    elif command -v iptables &>/dev/null; then
        echo "iptables"
    else
        warn "No supported firewall found (nft or iptables). Blocking will be disabled."
        echo "none"
    fi
}

require_command() {
    local cmd="$1"
    command -v "$cmd" &>/dev/null || error "Required command not found: $cmd"
}

require_docker_compose() {
    require_command docker
    docker compose version >/dev/null 2>&1 || error "docker compose is required"
}

compose_stack_up() {
    local compose_dir="$1"
    local build_flag="$2"

    if [[ -n "$build_flag" ]]; then
        (cd "$compose_dir" && docker compose up -d --build --force-recreate server dashboard)
    else
        (cd "$compose_dir" && docker compose up -d --force-recreate server dashboard)
    fi
}

extract_bind_host() {
    local addr="$1"

    if [[ "$addr" =~ ^\[([0-9a-fA-F:]+)\]:[0-9]+$ ]]; then
        echo "${BASH_REMATCH[1]}"
    elif [[ "$addr" == *:* ]]; then
        echo "${addr%:*}"
    else
        echo "$addr"
    fi
}

collect_auto_tls_sans() {
    local bind_host="${1:-}"
    local value
    declare -A seen=()

    add_san() {
        local candidate="$1"
        [[ -n "$candidate" ]] || return 0
        if [[ -z "${seen[$candidate]+x}" ]]; then
            seen["$candidate"]=1
            printf '%s\n' "$candidate"
        fi
    }

    add_san "localhost"
    add_san "127.0.0.1"

    if [[ -n "$bind_host" && "$bind_host" != "0.0.0.0" && "$bind_host" != "::" ]]; then
        add_san "$bind_host"
    fi

    if command -v hostname >/dev/null 2>&1; then
        for value in $(hostname -I 2>/dev/null || true); do
            add_san "$value"
        done
        add_san "$(hostname 2>/dev/null || true)"
    fi

    if command -v ip >/dev/null 2>&1; then
        while IFS= read -r value; do
            add_san "$value"
        done < <(ip -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
    fi
}

ensure_tls_certificates() {
    local repo_root="$1"
    local tls_dir="$2"
    local bind_host="$3"
    local regenerate="$4"
    shift 4
    local cert_path="$tls_dir/bannkenn.crt"
    local key_path="$tls_dir/bannkenn.key"
    local -a requested_sans=("$@")
    local -a effective_sans=()

    if [[ "$regenerate" != "true" && -f "$cert_path" && -f "$key_path" ]]; then
        return 0
    fi

    require_command openssl

    if [[ ${#requested_sans[@]} -gt 0 ]]; then
        effective_sans=("${requested_sans[@]}")
    else
        mapfile -t effective_sans < <(collect_auto_tls_sans "$bind_host")
    fi

    [[ ${#effective_sans[@]} -gt 0 ]] || error "Could not determine TLS SAN entries automatically. Re-run with one or more --tls-san values such as --tls-san 123.123.123.123"

    if [[ "$regenerate" == "true" ]]; then
        info "Regenerating self-signed TLS certificate in $tls_dir"
    else
        info "TLS certificate not found. Generating self-signed TLS certificate in $tls_dir"
    fi
    info "  SANs: ${effective_sans[*]}"

    bash "$repo_root/scripts/generate-ip-cert.sh" --out-dir "$tls_dir" "${effective_sans[@]}"

    info "TLS certificate ready:"
    info "  $cert_path"
    info "  $key_path"
}

install_from_cargo() {
    info "Building from source with cargo..."

    local repo_root
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

    # Build as the invoking user — rustup toolchains live in their home, not root's
    local build_user="${SUDO_USER:-$USER}"
    if ! sudo -iu "$build_user" bash -lc 'export PATH="$HOME/.cargo/bin:$PATH"; command -v cargo &>/dev/null'; then
        error "cargo not found for user '$build_user'. Install Rust: https://rustup.rs"
    fi

    info "Building bannkenn-agent as '$build_user' from $repo_root ..."
    sudo -iu "$build_user" bash -lc 'export PATH="$HOME/.cargo/bin:$PATH"; cargo build --release --manifest-path "'"$repo_root"'/Cargo.toml" --bin bannkenn-agent'

    install -m 755 "$repo_root/target/release/bannkenn-agent" "$INSTALL_DIR/$BINARY_NAME"
    info "Installed to $INSTALL_DIR/$BINARY_NAME"
}

deploy_dashboard_http() {
    local dashboard_url="$DEFAULT_HTTP_DASHBOARD_URL"
    local build_flag="--build"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dashboard-url)
                [[ $# -ge 2 ]] || error "--dashboard-url requires a value"
                dashboard_url="$2"
                shift 2
                ;;
            --no-build)
                build_flag=""
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                error "Unknown dashboard option: $1"
                ;;
        esac
    done

    require_docker_compose

    local repo_root compose_dir
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    compose_dir="$repo_root/docker"

    info "Starting BannKenn server/dashboard in plain HTTP mode"
    info "  Public API: http://SERVER_IP:3022"
    info "  Public dashboard: http://SERVER_IP:3021"
    info "  Dashboard upstream: $dashboard_url"

    (
        export BANNKENN_TLS_CERT_PATH=""
        export BANNKENN_TLS_KEY_PATH=""
        export BANNKENN_LOCAL_BIND=""
        export BANNKENN_DASHBOARD_SERVER_URL="$dashboard_url"
        compose_stack_up "$compose_dir" "$build_flag"
    )

    info ""
    info "Dashboard stack started."
    info "Verify with:"
    info "  curl http://127.0.0.1:3022/api/v1/health"
    info "  curl http://127.0.0.1:3021/api/health"
}

deploy_server_native_tls() {
    local tls_dir="$DEFAULT_TLS_DIR"
    local local_bind="$DEFAULT_LOCAL_BIND"
    local dashboard_url="$DEFAULT_TLS_DASHBOARD_URL"
    local build_flag="--build"
    local regenerate_cert="false"
    local -a tls_sans=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tls-dir)
                [[ $# -ge 2 ]] || error "--tls-dir requires a value"
                tls_dir="$2"
                shift 2
                ;;
            --tls-san)
                [[ $# -ge 2 ]] || error "--tls-san requires a value"
                tls_sans+=("$2")
                shift 2
                ;;
            --local-bind)
                [[ $# -ge 2 ]] || error "--local-bind requires a value"
                local_bind="$2"
                shift 2
                ;;
            --dashboard-url)
                [[ $# -ge 2 ]] || error "--dashboard-url requires a value"
                dashboard_url="$2"
                shift 2
                ;;
            --no-build)
                build_flag=""
                shift
                ;;
            --regenerate-cert)
                regenerate_cert="true"
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                error "Unknown server-native-tls option: $1"
                ;;
        esac
    done

    require_docker_compose

    local repo_root compose_dir cert_path key_path
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    compose_dir="$repo_root/docker"
    cert_path="$tls_dir/bannkenn.crt"
    key_path="$tls_dir/bannkenn.key"

    ensure_tls_certificates \
        "$repo_root" \
        "$tls_dir" \
        "$(extract_bind_host "0.0.0.0:3022")" \
        "$regenerate_cert" \
        "${tls_sans[@]}"

    info "Starting BannKenn server/dashboard with native TLS"
    info "  TLS host dir: $tls_dir"
    info "  Public HTTPS API: https://SERVER_IP:3022"
    info "  Local dashboard API: $dashboard_url"

    (
        export BANNKENN_SERVER_TLS_DIR="$tls_dir"
        export BANNKENN_TLS_CERT_PATH="/etc/bannkenn/tls/bannkenn.crt"
        export BANNKENN_TLS_KEY_PATH="/etc/bannkenn/tls/bannkenn.key"
        export BANNKENN_LOCAL_BIND="$local_bind"
        export BANNKENN_DASHBOARD_SERVER_URL="$dashboard_url"
        compose_stack_up "$compose_dir" "$build_flag"
    )

    info ""
    info "Native TLS stack started."
    info "Verify with:"
    info "  curl -vk https://127.0.0.1:3022/api/v1/health"
    info "  curl http://127.0.0.1:3023/api/v1/health"
}

main() {
    local mode="${1:-agent}"
    if [[ $# -gt 0 ]]; then
        shift
    fi

    case "$mode" in
        agent)
            ;;
        -h|--help)
            usage
            return
            ;;
        dashboard|dashboard-native-tls|server-native-tls)
            if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
                usage
                return
            fi
            ;;
        *)
            error "Unknown mode: $mode"
            ;;
    esac

    require_root

    if [[ "$mode" == "dashboard" ]]; then
        deploy_dashboard_http "$@"
        return
    fi

    if [[ "$mode" == "dashboard-native-tls" || "$mode" == "server-native-tls" ]]; then
        deploy_server_native_tls "$@"
        return
    fi

    info "BannKenn Agent Installer"
    info "========================"

    local firewall
    firewall=$(detect_firewall)
    info "Detected firewall: $firewall"

    # Install binary
    install_from_cargo

    # Create root config directory (service runs as root for firewall access)
    mkdir -p "$CONFIG_DIR"

    info ""
    info "Installation complete!"
    info "Next steps:"
    info "  1. sudo bannkenn-agent init     — configure the agent, install the systemd unit, and register if the dashboard is reachable"
    info "  2. sudo systemctl enable --now bannkenn-agent"
    info "  3. if registration failed during init: sudo bannkenn-agent connect && sudo systemctl restart bannkenn-agent"
}

main "$@"
