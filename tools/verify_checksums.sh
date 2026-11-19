#!/usr/bin/env bash
# ============================================================================
# Linux Forensic Collector (LFC) - checksum verifier
# ============================================================================
# Verifies SHA-256 checksums of downloaded release files against the
# published SHA256SUMS.txt.
#
# Usage:
#   ./verify_checksums.sh                    # verify files in current dir
#   ./verify_checksums.sh /path/to/downloads # verify files in given dir
#
# This script only computes and compares hashes. It never executes the files
# it verifies.
# ============================================================================
set -uo pipefail

DIR="${1:-.}"
[ -d "$DIR" ] || { echo "not a directory: $DIR" >&2; exit 2; }

SUMS="$DIR/SHA256SUMS.txt"
if [ ! -f "$SUMS" ]; then
  # Also accept a checksums file next to this script's download location.
  ALT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/SHA256SUMS.txt"
  if [ -f "$ALT" ]; then
    SUMS="$ALT"
  else
    echo "SHA256SUMS.txt not found in $DIR" >&2
    echo "Download it from the project page first." >&2
    exit 2
  fi
fi

command -v sha256sum >/dev/null 2>&1 || {
  echo "sha256sum is required (install coreutils)" >&2; exit 2; }

echo "Verifying downloads in: $(cd "$DIR" && pwd)"
echo "Checksum file:          $SUMS"
echo

FAILURES=0
CHECKED=0
while read -r EXPECTED FILENAME; do
  [ -n "${FILENAME:-}" ] || continue
  case "$EXPECTED" in \#*) continue ;; esac
  # sha256sum may prefix binary-mode entries with '*'.
  FILENAME="${FILENAME#\*}"
  TARGET="$DIR/$FILENAME"
  if [ ! -f "$TARGET" ]; then
    printf '  [MISS] %s (file not downloaded)\n' "$FILENAME"
    FAILURES=$((FAILURES + 1))
    continue
  fi
  ACTUAL=$(sha256sum "$TARGET" | awk '{print $1}')
  CHECKED=$((CHECKED + 1))
  if [ "$ACTUAL" = "$EXPECTED" ]; then
    printf '  [ OK ] %s\n' "$FILENAME"
  else
    printf '  [FAIL] %s\n' "$FILENAME"
    printf '         expected: %s\n' "$EXPECTED"
    printf '         actual:   %s\n' "$ACTUAL"
    FAILURES=$((FAILURES + 1))
  fi
done < "$SUMS"

echo
if [ "$CHECKED" -eq 0 ]; then
  echo "No files were checked - download the release files into $DIR first."
  exit 2
fi
if [ "$FAILURES" -eq 0 ]; then
  echo "All $CHECKED file(s) verified successfully."
  echo "It is now safe to review and run the collector."
  exit 0
fi
echo "$FAILURES problem(s) detected. DO NOT run unverified files."
exit 1
