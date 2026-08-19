#!/usr/bin/env bash
# Builds one CodeQL database per language from the fixtures and runs both the
# intra-procedural and interprocedural CWE-88 queries, asserting the matrix:
#
#   query           | vulnerable | vulnerable_wrapped | safe_fixed
#   ----------------|-----------:|-------------------:|----------:
#   intra-procedural|     1      |         0          |     0
#   interprocedural |     1      |         1          |     0
#
# The interprocedural query is what additionally catches the launch-wrapper
# idiom that the intra-procedural query (and Semgrep) miss.
#
# Requirements: a current CodeQL CLI (>= 2.26; older CLIs cannot fetch the
# current standard-library packs). Override with CODEQL=/path/to/codeql. The
# fixtures are self-contained, so no compiler/build is needed
# (--build-mode=none for Java/C; Python and JavaScript need no build).
set -eu

DET=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CODEQL=${CODEQL:-codeql}

command -v "$CODEQL" >/dev/null 2>&1 || {
    echo "[SKIP] codeql not found on PATH (set CODEQL=/path/to/codeql)" >&2
    exit 2
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

count() { # $1 = sarif file, $2 = fixture basename
    python3 - "$1" "$2" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
b = sys.argv[2]
n = 0
for r in d["runs"][0].get("results", []):
    uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    if uri.split("/")[-1] == b:
        n += 1
print(n)
PY
}

fail=0
check() { # lang qldir fixdir langflag buildmode vuln wrapped safe
    lang=$1; qldir=$2; fix=$3; langflag=$4; buildmode=$5; v=$6; w=$7; s=$8
    db="$WORK/db-$lang"

    ( cd "$DET/$qldir" && "$CODEQL" pack install >/dev/null 2>&1 )

    if [ -n "$buildmode" ]; then
        "$CODEQL" database create "$db" --language="$langflag" --build-mode=none \
            --source-root="$DET/fixtures/$fix" --overwrite >/dev/null 2>&1
    else
        "$CODEQL" database create "$db" --language="$langflag" \
            --source-root="$DET/fixtures/$fix" --overwrite >/dev/null 2>&1
    fi

    intra="$WORK/$lang-intra.sarif"
    inter="$WORK/$lang-inter.sarif"
    "$CODEQL" database analyze "$db" "$DET/$qldir/embedded-suboption-injection.ql" \
        --format=sarifv2.1.0 --output="$intra" --rerun >/dev/null 2>&1
    "$CODEQL" database analyze "$db" "$DET/$qldir/embedded-suboption-injection-interprocedural.ql" \
        --format=sarifv2.1.0 --output="$inter" --rerun >/dev/null 2>&1

    iav=$(count "$intra" "$v"); iaw=$(count "$intra" "$w"); ias=$(count "$intra" "$s")
    ipv=$(count "$inter" "$v"); ipw=$(count "$inter" "$w"); ips=$(count "$inter" "$s")

    printf "%-11s intra: %s=%s %s=%s %s=%s | inter: %s=%s %s=%s %s=%s\n" \
        "$lang" "$v" "$iav" "$w" "$iaw" "$s" "$ias" "$v" "$ipv" "$w" "$ipw" "$s" "$ips"

    if [ "$iav" != 1 ] || [ "$iaw" != 0 ] || [ "$ias" != 0 ]; then
        echo "  [FAIL] $lang intra: expected vulnerable=1, vulnerable_wrapped=0, safe_fixed=0" >&2
        fail=1
    fi
    if [ "$ipv" != 1 ] || [ "$ipw" != 1 ] || [ "$ips" != 0 ]; then
        echo "  [FAIL] $lang inter: expected vulnerable=1, vulnerable_wrapped=1, safe_fixed=0" >&2
        fail=1
    fi
}

check python     codeql/python     python     python     ""                 vulnerable.py   vulnerable_wrapped.py  safe_fixed.py
check java       codeql/java       java       java       "--build-mode=none" Vulnerable.java VulnerableWrapped.java SafeFixed.java
check javascript codeql/javascript javascript javascript ""                 vulnerable.js   vulnerable_wrapped.js  safe_fixed.js
check c          codeql/cpp        c          cpp        "--build-mode=none" vulnerable.c    vulnerable_wrapped.c   safe_fixed.c

if [ "$fail" = 0 ]; then
    echo "[PASS] all CodeQL detection matrices are correct (intra misses the wrapper; interprocedural catches it)"
else
    echo "[FAIL] one or more CodeQL matrices did not match" >&2
    exit 1
fi
