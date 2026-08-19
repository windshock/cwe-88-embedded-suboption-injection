#!/usr/bin/env bash
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SUBMISSION="$ROOT/submission"
DIST="$ROOT/dist"
NAME="cwe-88-embedded-suboption-injection-submission"
STAGE="$DIST/$NAME"
ZIP="$DIST/$NAME.zip"

command -v zip >/dev/null 2>&1 || {
    echo "error: zip is required" >&2
    exit 2
}
command -v sha256sum >/dev/null 2>&1 || {
    echo "error: sha256sum is required" >&2
    exit 2
}

# Fail early if product-specific material, compiled artifacts, required files,
# or the committed integrity manifest are not in the expected state.
bash "$ROOT/tools/validate-submission.sh"

rm -rf "$DIST"
mkdir -p "$STAGE"

# Verify the generalized weakness behavior before packaging it.
(
    cd "$SUBMISSION"
    bash scripts/run_demo.sh
)

# Copy only the canonical submission material. Do not ship locally compiled
# binaries, object files, caches, or repository metadata.
(
    cd "$SUBMISSION"
    find . -type f \
        ! -path './poc/demo_target' \
        ! -name '*.o' \
        ! -name '*.pyc' \
        ! -path '*/__pycache__/*' \
        -print
) | while IFS= read -r rel; do
    rel=${rel#./}
    mkdir -p "$STAGE/$(dirname "$rel")"
    cp "$SUBMISSION/$rel" "$STAGE/$rel"
done

# Include repository-level scope/license notices with the submission set.
cp "$ROOT/NOTICE.md" "$STAGE/NOTICE.md"
cp "$ROOT/LICENSE" "$STAGE/LICENSE"

(
    cd "$DIST"
    zip -X -q -r "$(basename "$ZIP")" "$NAME"
    sha256sum "$(basename "$ZIP")" > "$(basename "$ZIP").sha256"
)

rm -rf "$STAGE"

echo "[PASS] submission package created"
echo "       $ZIP"
echo "       $ZIP.sha256"
