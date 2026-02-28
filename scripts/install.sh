#!/usr/bin/env bash
# BannKenn Agent Installer
# Usage: curl -sSL https://raw.githubusercontent.com/your-org/bannkenn/main/scripts/install.sh | bash

set -euo pipefail

BINARY_NAME="bannkenn-agent"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/root/.config/bannkenn"
VERSION="${BANNKENN_VERSION:-latest}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

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

configure_systemd() {
    cat > /etc/systemd/system/bannkenn-agent.service <<EOF
[Unit]
Description=BannKenn IPS Agent
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${BINARY_NAME}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable bannkenn-agent
    info "Systemd service installed and enabled."
}

main() {
    require_root

    info "BannKenn Agent Installer"
    info "========================"

    local firewall
    firewall=$(detect_firewall)
    info "Detected firewall: $firewall"

    # Install binary
    install_from_cargo

    # Install and enable systemd service unit
    configure_systemd

    # Create root config directory (service runs as root for firewall access)
    mkdir -p "$CONFIG_DIR"

    info ""
    info "Installation complete!"
    info "Run 'sudo bannkenn-agent init' to configure the agent interactively."
    info "Then start with: sudo systemctl start bannkenn-agent"
}

main "$@"
