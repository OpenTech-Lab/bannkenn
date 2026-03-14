#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT_DIR/agent/ebpf/containment.bpf.c"
OUT="$ROOT_DIR/agent/ebpf/bannkenn-containment.bpf.o"

clang \
  -I/usr/include/x86_64-linux-gnu \
  -O2 \
  -g \
  -target bpf \
  -Wall \
  -Werror \
  -c "$SRC" \
  -o "$OUT"

printf 'Built %s\n' "$OUT"
