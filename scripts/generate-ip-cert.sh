#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${BANNKENN_ENV_FILE:-$REPO_ROOT/.env}"

load_repo_env() {
    local env_file="${1:-$ENV_FILE}"

    if [[ -f "$env_file" ]]; then
        set -a
        # shellcheck disable=SC1090
        source "$env_file"
        set +a
    fi
}

load_repo_env

usage() {
    echo "Usage: $0 [--out-dir DIR] <ip-or-host> [ip-or-host ...]" >&2
    echo "       $0 [--out-dir DIR]    # uses BANNKENN_TLS_SANS or BANNKENN_PUBLIC_ADDRESS from .env" >&2
    echo "Examples:" >&2
    echo "  cp .env.example .env && edit .env" >&2
    echo "  $0" >&2
    echo "  $0 192.0.2.10" >&2
    echo "  $0 192.0.2.10 /etc/nginx/ssl" >&2
    echo "  $0 --out-dir /etc/nginx/ssl 192.0.2.10 198.51.100.24" >&2
    echo "  $0 --out-dir /etc/nginx/ssl 192.0.2.10 example.internal" >&2
}

is_ip_san() {
    local value="$1"
    [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || "$value" == *:* ]]
}

output_dir="${BANNKENN_TLS_DIR:-/etc/nginx/ssl}"
declare -a san_entries=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out-dir)
            if [[ $# -lt 2 ]]; then
                usage
                exit 1
            fi
            output_dir="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            san_entries+=("$1")
            shift
            ;;
    esac
done

if [[ ${#san_entries[@]} -eq 0 ]]; then
    if [[ -n "${BANNKENN_TLS_SANS:-}" ]]; then
        # shellcheck disable=SC2206
        san_entries=(${BANNKENN_TLS_SANS})
    elif [[ -n "${BANNKENN_PUBLIC_ADDRESS:-}" ]]; then
        san_entries=("${BANNKENN_PUBLIC_ADDRESS}")
    else
        usage
        echo >&2
        echo "No SAN entries provided. Set BANNKENN_TLS_SANS or BANNKENN_PUBLIC_ADDRESS in .env, or pass IP/hostname arguments." >&2
        exit 1
    fi
fi

# Backward compatibility with the old form:
#   generate-ip-cert.sh 192.0.2.10 /etc/nginx/ssl
if [[ ${#san_entries[@]} -eq 2 && "${san_entries[1]}" == */* ]]; then
    output_dir="${san_entries[1]}"
    san_entries=("${san_entries[0]}")
fi

primary_name="${san_entries[0]}"
cert_path="$output_dir/bannkenn.crt"
key_path="$output_dir/bannkenn.key"
tmp_config="$(mktemp)"

cleanup() {
    rm -f "$tmp_config"
}
trap cleanup EXIT

mkdir -p "$output_dir"

{
cat <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = $primary_name

[v3_req]
subjectAltName = @alt_names
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
EOF
} >"$tmp_config"

dns_index=1
ip_index=1
for san in "${san_entries[@]}"; do
    if is_ip_san "$san"; then
        printf 'IP.%d = %s\n' "$ip_index" "$san" >>"$tmp_config"
        ((ip_index += 1))
    else
        printf 'DNS.%d = %s\n' "$dns_index" "$san" >>"$tmp_config"
        ((dns_index += 1))
    fi
done

openssl req \
    -x509 \
    -nodes \
    -newkey rsa:4096 \
    -sha256 \
    -days 825 \
    -keyout "$key_path" \
    -out "$cert_path" \
    -config "$tmp_config" \
    -extensions v3_req

echo "Generated:"
echo "  $cert_path"
echo "  $key_path"
echo
echo "Install/trust this certificate (or its issuing CA) on every agent/browser"
printf 'whose address matches one of these SAN entries: %s\n' "${san_entries[*]}"
