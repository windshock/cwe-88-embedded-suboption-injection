#!/usr/bin/env bash
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
POC="$ROOT/poc"
TARGET="$POC/demo_target"

cc -std=c11 -Wall -Wextra -Werror -O2 "$POC/demo_target.c" -o "$TARGET"

run_case() {
    name=$1
    shift
    out=$(mktemp)
    trap 'rm -f "$out"' EXIT HUP INT TERM

    python3 "$POC/caller.py" "$name" --target "$TARGET" >"$out" 2>&1
    cat "$out"

    for expected in "$@"; do
        if ! grep -F -- "$expected" "$out" >/dev/null; then
            echo "[FAIL] $name: missing expected line: $expected" >&2
            exit 1
        fi
    done

    echo "[PASS] $name"
    rm -f "$out"
    trap - EXIT HUP INT TERM
}

echo "=== control: untrusted field contains no delimiter ==="
run_case control \
    "[caller] list_elements=3" \
    "[caller] shell=False" \
    "[target] argc=3" \
    "[result] parsed_options=2" \
    "[result] endpoint_occurrences=1" \
    "[result] endpoint=trusted.example" \
    "[result] id=42" \
    "[result] log_target=unset"

echo
echo "=== inject-new: delimiter creates a previously absent sibling sub-option ==="
run_case inject-new \
    "[caller] list_elements=3" \
    "[target] argc=3" \
    "[target] argv[2]=<endpoint=trusted.example,id=42,log_target=attacker.example>" \
    "[result] parsed_options=3" \
    "[result] endpoint=trusted.example" \
    "[result] log_target=attacker.example"

echo
echo "=== override: delimiter creates a duplicate security-sensitive sub-option ==="
run_case override \
    "[caller] list_elements=3" \
    "[target] argc=3" \
    "[target] argv[2]=<endpoint=trusted.example,id=42,endpoint=attacker.example>" \
    "[result] parsed_options=3" \
    "[result] endpoint_occurrences=2" \
    "[result] endpoint=attacker.example"

echo
echo "[PASS] all generalized CWE-88 embedded sub-option tests passed"
