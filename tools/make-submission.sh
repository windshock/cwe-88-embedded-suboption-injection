#!/usr/bin/env bash
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SUBMISSION="$ROOT/submission"
DIST="$ROOT/dist"
NAME="cwe-88-embedded-suboption-injection-submission"
STAGE="$DIST/$NAME"
ZIP="$DIST/$NAME.zip"

command -v git >/dev/null 2>&1 || {
    echo "error: git is required to identify canonical tracked submission files" >&2
    exit 2
}
command -v zip >/dev/null 2>&1 || {
    echo "error: zip is required" >&2
    exit 2
}
command -v sha256sum >/dev/null 2>&1 || {
    echo "error: sha256sum is required" >&2
    exit 2
}

git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
    echo "error: run this builder from a git checkout of the repository" >&2
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

# Package only files that are tracked by git below submission/. This prevents
# editor backups, local experiment files, compiled artifacts, or unrelated
# disclosure material from being swept into the ZIP by a broad directory copy.
git -C "$ROOT" ls-files 'submission/**' | while IFS= read -r tracked; do
    rel=${tracked#submission/}
    [ "$rel" != "$tracked" ] || continue
    mkdir -p "$STAGE/$(dirname "$rel")"
    cp "$ROOT/$tracked" "$STAGE/$rel"
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

echo "[PASS] submission package created from tracked canonical files"
echo "       $ZIP"
echo "       $ZIP.sha256"
