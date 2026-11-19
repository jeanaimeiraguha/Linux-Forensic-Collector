#!/usr/bin/env bash
# =============================================================================
# tests/run_tests.sh - runs the complete LFC test suite
# =============================================================================
#   1. Python unit/integration tests (stdlib unittest, no pytest needed)
#   2. Bash unit tests for lib/common.sh
#   3. End-to-end smoke test (full collection run on a fixture tree)
#
# Usage:  ./tests/run_tests.sh [--quick]
#   --quick   skip the end-to-end smoke test (slower)
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

PY="$(cd "$ROOT" && bash -c 'source lib/common.sh && lfc_python' 2>/dev/null || true)"
[ -n "${PY:-}" ] || PY=python

TOTAL_FAIL=0
SUMMARY=()

banner() { printf '\n=== %s ===\n' "$1"; }

# --- 1. Python tests ---------------------------------------------------------
banner "Python tests (unittest)"
if (cd "$ROOT" && $PY -m unittest discover -s tests/python -t . 2>&1); then
  SUMMARY+=("python: PASS")
else
  SUMMARY+=("python: FAIL")
  TOTAL_FAIL=$((TOTAL_FAIL + 1))
fi

# --- 2. Bash unit tests ------------------------------------------------------
banner "Bash tests (lib/common.sh)"
if bash "$ROOT/tests/bash/test_common.sh"; then
  SUMMARY+=("common: PASS")
else
  SUMMARY+=("common: FAIL")
  TOTAL_FAIL=$((TOTAL_FAIL + 1))
fi

# --- 3. Smoke test -----------------------------------------------------------
if [ "$QUICK" = "1" ]; then
  banner "Smoke test (skipped: --quick)"
  SUMMARY+=("smoke: SKIP")
else
  banner "End-to-end smoke test"
  if bash "$ROOT/tests/bash/test_smoke.sh"; then
    SUMMARY+=("smoke: PASS")
  else
    SUMMARY+=("smoke: FAIL")
    TOTAL_FAIL=$((TOTAL_FAIL + 1))
  fi
fi

# --- Summary -----------------------------------------------------------------
banner "Summary"
for line in "${SUMMARY[@]}"; do
  printf '  %s\n' "$line"
done
printf '\n'
if [ "$TOTAL_FAIL" -eq 0 ]; then
  printf 'ALL TEST SUITES PASSED\n'
  exit 0
fi
printf '%d SUITE(S) FAILED\n' "$TOTAL_FAIL"
exit 1
