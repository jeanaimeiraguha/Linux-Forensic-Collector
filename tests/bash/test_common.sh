#!/usr/bin/env bash
# =============================================================================
# tests/bash/test_common.sh - unit tests for lib/common.sh helpers
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
source "$ROOT/lib/common.sh"

PASS=0
FAIL=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ok()   { PASS=$((PASS + 1)); printf '  [ OK ] %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$1"; }

assert_eq() { # <desc> <expected> <actual>
  if [ "$2" = "$3" ]; then ok "$1"; else
    bad "$1 (expected=$(printf '%q' "$2") actual=$(printf '%q' "$3"))"
  fi
}

assert_true() { # <desc> <cmd...>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi
}

assert_false() { # <desc> <cmd...>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then bad "$desc"; else ok "$desc"; fi
}

printf 'test_common.sh\n'

# --- lfc_escape_into ---------------------------------------------------------
lfc_escape_into 'plain'
assert_eq "escape: plain unchanged" 'plain' "$LFC_ESCAPED"

lfc_escape_into $'a\tb'
assert_eq "escape: tab becomes \\t" 'a\tb' "$LFC_ESCAPED"

lfc_escape_into $'a\nb'
assert_eq "escape: newline becomes \\n" 'a\nb' "$LFC_ESCAPED"

lfc_escape_into $'a\rb'
assert_eq "escape: CR becomes \\r" 'a\rb' "$LFC_ESCAPED"

lfc_escape_into 'a\b'
assert_eq "escape: backslash doubles" 'a\\b' "$LFC_ESCAPED"

lfc_escape_into $'x\t\\\ny'
assert_eq "escape: combined" 'x\t\\\ny' "$LFC_ESCAPED"

# Cross-boundary round trip: bash escapes -> Python unescapes.
PY="$(lfc_python || true)"
if [ -n "${PY:-}" ]; then
  ORIG=$'dir/with\ttab and \\slash and "quotes"'
  lfc_escape_into "$ORIG"
  GOT=$(cd "$ROOT" && printf '%s' "$LFC_ESCAPED" | $PY -c \
    'import sys; from collector.fragments import unescape; sys.stdout.write(unescape(sys.stdin.read()))')
  assert_eq "roundtrip: bash escape -> python unescape" "$ORIG" "$GOT"
else
  printf '  [SKIP] roundtrip (no python available)\n'
fi

# --- lfc_tsv_header / lfc_tsv_row -------------------------------------------
TSV="$TMP/rows.tsv"
lfc_tsv_header "$TSV" a b
lfc_tsv_row "$TSV" "one" "two"
lfc_tsv_row "$TSV" $'tab\there' 'back\slash'
assert_eq "tsv: header line" $'a\tb' "$(head -n1 "$TSV")"
assert_eq "tsv: plain row" $'one\ttwo' "$(sed -n '2p' "$TSV")"
# Row values are stored ESCAPED (literal backslash-t), round-tripped later
# by collector.fragments.unescape.
assert_eq "tsv: escaped row" $'tab\\there\tback\\\\slash' "$(sed -n '3p' "$TSV")"

# --- lfc_tsv_kv --------------------------------------------------------------
KV="$TMP/kv.tsv"
lfc_tsv_header "$KV" key value
lfc_tsv_kv "$KV" "hostname" "host-1"
assert_eq "tsv: kv row" $'hostname\thost-1' "$(sed -n '2p' "$KV")"

# --- lfc_module_enabled ------------------------------------------------------
LFC_SKIP_MODULES=()
LFC_ONLY_MODULES=()
LFC_CFG=([collection.modules.system]=true [collection.modules.media]=false)
assert_true  "module: enabled by default" lfc_module_enabled system
assert_false "module: disabled via config" lfc_module_enabled media

LFC_SKIP_MODULES=(network)
assert_false "module: skipped via CLI" lfc_module_enabled network
assert_true  "module: others still on" lfc_module_enabled system
LFC_SKIP_MODULES=()

LFC_ONLY_MODULES=(software)
assert_true  "module: only-list hit" lfc_module_enabled software
assert_false "module: only-list miss" lfc_module_enabled system
LFC_ONLY_MODULES=()

# --- lfc_human_bytes ---------------------------------------------------------
assert_eq "human: zero" "0B" "$(lfc_human_bytes 0)"
# Exact formatting depends on numfmt availability ("1KB" vs "1.0KB").
case "$(lfc_human_bytes 1024)" in
  1*KB) ok "human: 1024 -> 1*KB" ;;
  *) bad "human: 1024 (got: $(lfc_human_bytes 1024))" ;;
esac
case "$(lfc_human_bytes 1536)" in
  1.*KB|1KB) ok "human: 1536 -> 1*KB" ;;
  *) bad "human: 1536 (got: $(lfc_human_bytes 1536))" ;;
esac
case "$(lfc_human_bytes 1073741824)" in
  1*GB) ok "human: 1 GiB -> 1*GB" ;;
  *) bad "human: 1 GiB (got: $(lfc_human_bytes 1073741824))" ;;
esac

# --- lfc_have / lfc_first ----------------------------------------------------
assert_true  "have: sh exists" lfc_have sh
assert_false "have: nonsense missing" lfc_have definitely-not-a-command-xyz
FIRST="$(lfc_first sh definitely-not-a-command-xyz || true)"
assert_eq "first: returns sh" "$(command -v sh)" "$FIRST"
assert_false "first: all missing fails" lfc_first no-cmd-a no-cmd-b

# --- lfc_audit ---------------------------------------------------------------
AUDIT="$TMP/audit.log"
: > "$AUDIT"
LFC_AUDIT_LOG="$AUDIT"
LFC_STAGE=unit
LFC_MODULE=common
LFC_VERBOSE=0
lfc_audit "OK" "hello world"
LINE="$(tail -n1 "$AUDIT")"
case "$LINE" in
  *"| OK | stage=unit | module=common |"*"| hello world") ok "audit: format" ;;
  *) bad "audit: format (got: $LINE)" ;;
esac

# audit must not crash without a log path
LFC_AUDIT_LOG=""
lfc_audit "OK" "no log configured"
RC=$?
assert_eq "audit: no log path ok" "0" "$RC"

# --- lfc_record_skip / error -------------------------------------------------
LFC_RAW_DIR="$TMP/raw"
mkdir -p "$LFC_RAW_DIR"
lfc_tsv_header "$LFC_RAW_DIR/skipped.tsv" module operation reason
lfc_tsv_header "$LFC_RAW_DIR/errors.tsv" module operation message
LFC_AUDIT_LOG="$AUDIT"
lfc_record_skip "network" "ss" "command not available"
assert_eq "skip: row written" $'network\tss\tcommand not available' \
  "$(sed -n '2p' "$LFC_RAW_DIR/skipped.tsv")"
lfc_record_error "media" "scan" "disk went away"
assert_eq "error: row written" $'media\tscan\tdisk went away' \
  "$(sed -n '2p' "$LFC_RAW_DIR/errors.tsv")"

# --- lfc_confirm -------------------------------------------------------------
LFC_NON_INTERACTIVE=1
assert_false "confirm: non-interactive refuses" lfc_confirm "continue?"
LFC_NON_INTERACTIVE=0

# --- lfc_am_root -------------------------------------------------------------
if [ "$(id -u 2>/dev/null || echo 1000)" = "0" ]; then
  assert_true "root: detected" lfc_am_root
else
  assert_false "root: not detected for normal user" lfc_am_root
fi

# --- lfc_ts ------------------------------------------------------------------
TS="$(lfc_ts)"
case "$TS" in
  ????-??-??T??:??:??Z) ok "ts: UTC format" ;;
  *) bad "ts: UTC format (got: $TS)" ;;
esac

printf '\ncommon.sh: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
