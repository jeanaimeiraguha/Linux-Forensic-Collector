#!/usr/bin/env bash
# ============================================================================
# Linux Forensic Collector (LFC) - release builder
# ============================================================================
# Creates a distributable release archive, computes SHA-256 checksums and
# publishes download artifacts + SHA256SUMS.txt for the web landing page.
#
# Usage:  ./tools/build_release.sh [--version X.Y.Z]
#
# Output:
#   dist/lfc-<version>.tar.gz        release archive
#   dist/SHA256SUMS.txt              checksums for dist artifacts
#   web/downloads/lfc-<version>.tar.gz   published copy
#   web/downloads/lfc.sh             published single script
#   web/SHA256SUMS.txt               checksums shown on the landing page
# ============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION=""

while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || { echo "--version requires a value" >&2; exit 2; }
      VERSION="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$VERSION" ]; then
  # Version is declared once, in lib/common.sh (sourced by lfc.sh).
  VERSION=$(sed -n 's/^LFC_VERSION="\([^"]*\)".*/\1/p' \
    "$ROOT/lib/common.sh" 2>/dev/null | head -1)
fi
[ -n "$VERSION" ] || { echo "could not determine version" >&2; exit 1; }

command -v tar  >/dev/null 2>&1 || { echo "tar is required"  >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 1; }

STAGE="$ROOT/dist/staging/linux-forensic-collector"
ARCHIVE="$ROOT/dist/lfc-$VERSION.tar.gz"
rm -rf "$ROOT/dist/staging"
mkdir -p "$STAGE/lib" "$STAGE/collector" "$STAGE/config" "$STAGE/docs" \
         "$ROOT/dist" "$ROOT/web/downloads"

echo "Building Linux Forensic Collector v$VERSION ..."

# --- Copy payload ------------------------------------------------------------
cp "$ROOT/lfc.sh"      "$STAGE/"
cp "$ROOT/install.sh"  "$STAGE/"
cp "$ROOT/lib/"*.sh    "$STAGE/lib/"
cp "$ROOT/collector/"*.py "$STAGE/collector/"
cp "$ROOT/config/config.template.json" "$STAGE/config/"

for DOC in README.md SECURITY.md; do
  if [ -f "$ROOT/$DOC" ]; then cp "$ROOT/$DOC" "$STAGE/"; fi
done
if [ -d "$ROOT/docs" ]; then
  find "$ROOT/docs" -maxdepth 1 -type f -name '*.md' -exec cp {} "$STAGE/docs/" \;
fi
if [ -f "$ROOT/tools/verify_checksums.sh" ]; then
  mkdir -p "$STAGE/tools"
  cp "$ROOT/tools/verify_checksums.sh" "$STAGE/tools/"
fi

# Ship the test suite so operators can verify the release themselves.
if [ -d "$ROOT/tests" ]; then
  mkdir -p "$STAGE/tests/bash" "$STAGE/tests/python"
  cp "$ROOT/tests/run_tests.sh" "$STAGE/tests/" 2>/dev/null || true
  cp "$ROOT/tests/bash/"*.sh "$STAGE/tests/bash/" 2>/dev/null || true
  cp "$ROOT/tests/python/"*.py "$STAGE/tests/python/" 2>/dev/null || true
  cp "$ROOT/tests/__init__.py" "$STAGE/tests/" 2>/dev/null || true
  cp "$ROOT/tests/python/__init__.py" "$STAGE/tests/python/" 2>/dev/null || true
  chmod +x "$STAGE/tests/run_tests.sh" "$STAGE/tests/bash/"*.sh 2>/dev/null || true
fi

# Strip bytecode / editor droppings
find "$STAGE" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null
find "$STAGE" -name '*.pyc' -delete 2>/dev/null
find "$STAGE" -name '.DS_Store' -delete 2>/dev/null

chmod +x "$STAGE/lfc.sh" "$STAGE/install.sh" 2>/dev/null
[ -f "$STAGE/tools/verify_checksums.sh" ] && chmod +x "$STAGE/tools/verify_checksums.sh"

# --- Archive -----------------------------------------------------------------
tar -czf "$ARCHIVE" -C "$ROOT/dist/staging" linux-forensic-collector
echo "  archive: ${ARCHIVE#$ROOT/}"

# --- Publish to web/downloads ------------------------------------------------
cp "$ARCHIVE" "$ROOT/web/downloads/"
cp "$ROOT/lfc.sh" "$ROOT/web/downloads/lfc.sh"

# --- Checksums ---------------------------------------------------------------
( cd "$ROOT/dist" && sha256sum "lfc-$VERSION.tar.gz" > SHA256SUMS.txt )

( cd "$ROOT/web/downloads" && \
  { [ -f "lfc-$VERSION.tar.gz" ] && sha256sum "lfc-$VERSION.tar.gz"; \
    [ -f lfc.sh ] && sha256sum lfc.sh; } > "$ROOT/web/SHA256SUMS.txt" )

echo "  checksums: web/SHA256SUMS.txt, dist/SHA256SUMS.txt"
echo "Done. Publish the web/ directory to your site."

cat "$ROOT/web/SHA256SUMS.txt"
