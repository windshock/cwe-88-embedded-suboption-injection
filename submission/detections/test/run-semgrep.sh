#!/usr/bin/env bash
# Runs the CWE-88 embedded sub-option injection Semgrep rules against the
# fixtures for all four languages and asserts the intra-procedural matrix:
#   vulnerable=1, vulnerable_wrapped=0, safe_fixed=0
#
# The Semgrep rules are intentionally intra-procedural, so they flag the direct
# construction only. The launch-wrapper case is covered by the interprocedural
# CodeQL query (see run-codeql.sh).
#
# Override the tool with SEMGREP=/path/to/semgrep. No compiler or build needed.
set -eu

DET=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SEMGREP=${SEMGREP:-semgrep}

command -v "$SEMGREP" >/dev/null 2>&1 || {
    echo "[SKIP] semgrep not found on PATH (set SEMGREP=/path/to/semgrep)" >&2
    exit 2
}

count() { # $1 = semgrep json file, $2 = fixture basename
    python3 - "$1" "$2" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
b = sys.argv[2]
print(sum(1 for r in d.get("results", []) if r["path"].split("/")[-1] == b))
PY
}

fail=0
check() { # lang rule fixdir vuln wrapped safe
    lang=$1; rule=$2; fix=$3; v=$4; w=$5; s=$6
    out=$(mktemp)
    "$SEMGREP" --config "$DET/semgrep/$rule" "$DET/fixtures/$fix" \
        --json --quiet --metrics=off >"$out" 2>/dev/null || true
    cv=$(count "$out" "$v"); cw=$(count "$out" "$w"); cs=$(count "$out" "$s")
    printf "%-11s semgrep: %s=%s %s=%s %s=%s\n" "$lang" "$v" "$cv" "$w" "$cw" "$s" "$cs"
    if [ "$cv" != 1 ] || [ "$cw" != 0 ] || [ "$cs" != 0 ]; then
        echo "  [FAIL] $lang: expected vulnerable=1, vulnerable_wrapped=0, safe_fixed=0" >&2
        fail=1
    fi
    rm -f "$out"
}

check python     cwe88_embedded_suboption_injection_python.yml python     vulnerable.py         vulnerable_wrapped.py  safe_fixed.py
check java       cwe88_embedded_suboption_injection_java.yml   java       Vulnerable.java       VulnerableWrapped.java SafeFixed.java
check javascript cwe88_embedded_suboption_injection_js.yml     javascript vulnerable.js         vulnerable_wrapped.js  safe_fixed.js
check c          cwe88_embedded_suboption_injection_c.yml      c          vulnerable.c          vulnerable_wrapped.c   safe_fixed.c

if [ "$fail" = 0 ]; then
    echo "[PASS] all Semgrep intra-procedural detection matrices are correct"
else
    echo "[FAIL] one or more Semgrep matrices did not match" >&2
    exit 1
fi
