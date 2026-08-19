#!/usr/bin/env bash
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

POC="poc"
TARGET="./poc/demo_target"
EVIDENCE="evidence"
mkdir -p "$EVIDENCE"

{
    echo "=== toolchain ==="
    cc --version | head -n 1
    python3 --version
    uname -srmo
    echo
    echo "=== build ==="
    cc -std=c11 -Wall -Wextra -Werror -O2 "$POC/demo_target.c" -o "$TARGET"
    echo "build_exit=0"
} > "$EVIDENCE/build_log.txt" 2>&1

{
    bash scripts/run_demo.sh
    echo "run_demo_exit=0"
} > "$EVIDENCE/run_demo.txt" 2>&1

sha256sum \
    poc/demo_target.c \
    poc/caller.py \
    scripts/run_demo.sh \
    > "$EVIDENCE/sha256.txt"

rm -f "$TARGET"

echo "[PASS] evidence refreshed under submission/evidence/"
