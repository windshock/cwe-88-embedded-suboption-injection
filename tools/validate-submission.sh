#!/usr/bin/env bash
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SUBMISSION="$ROOT/submission"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

for required in \
    README.md \
    FORM-TEXT.md \
    form-description.txt \
    modification-details.md \
    PRECEDENTS.md \
    REVIEWER-NOTES.md \
    SUBMISSION-CHECKLIST.md \
    EXPECTED-RESULTS.md \
    poc/demo_target.c \
    poc/caller.py \
    scripts/run_demo.sh \
    evidence/sha256.txt; do
    [ -f "$SUBMISSION/$required" ] || fail "missing required submission file: $required"
done

# Product-independent submission boundary. These tokens belong to the separately
# coordinated product report and must not accidentally leak into this generalized
# CWE demonstrator package.
if grep -R -n -i -E \
    'NHN[[:space:]_-]*KCP|pp_cli|pa_url|pa_port|ordr_idxx' \
    "$SUBMISSION"; then
    fail "product-specific identifier detected in canonical submission material"
fi

# Do not submit compiled or packaged executable artifacts. Source and captured
# textual evidence are sufficient to reproduce the generalized weakness class.
for pattern in '*.exe' '*.dll' '*.so' '*.dylib' '*.o' '*.obj' '*.class' '*.jar'; do
    found=$(find "$SUBMISSION" -type f -name "$pattern" -print -quit)
    [ -z "$found" ] || fail "compiled artifact found in canonical submission set: $found"
done

# The locally built Linux demo target has no extension, so check it explicitly.
[ ! -f "$SUBMISSION/poc/demo_target" ] || fail "locally built poc/demo_target must not be committed or packaged"

# Verify that the committed core source/scripts still match the captured manifest.
(
    cd "$SUBMISSION"
    sha256sum -c evidence/sha256.txt
) || fail "core demonstrator integrity check failed"

echo "[PASS] required submission files present"
echo "[PASS] no restricted product-specific identifiers found"
echo "[PASS] no compiled artifacts found in canonical submission material"
echo "[PASS] core demonstrator integrity manifest verified"
echo "[PASS] submission hygiene validation passed"
