#!/usr/bin/env bash
# =============================================================================
# lib/common.sh — Shared helpers for Linux Forensic Collector (LFC)
# =============================================================================
# Sourced by lfc.sh and every module. Provides:
#   * console logging (stderr only, keeps stdout clean for data)
#   * tamper-evident audit trail ($LFC_AUDIT_LOG)
#   * tab-separated fragment writers with escaping
#   * command availability probes and safe fallbacks
#   * Python interpreter resolution
#
# NOTE: LFC deliberately does NOT use `set -e`. A forensic collector must
# record failures and keep collecting instead of aborting mid-run.
# =============================================================================

LFC_VERSION="1.0.0"
LFC_TOOL_NAME="Linux Forensic Collector (LFC)"

# ---------------------------------------------------------------------------
# Console logging — everything goes to stderr
# ---------------------------------------------------------------------------
lfc_log()   { printf '[INFO ] %s\n' "$*" >&2; }
lfc_warn()  { printf '[WARN ] %s\n' "$*" >&2; }
lfc_error() { printf '[ERROR] %s\n' "$*" >&2; }
lfc_die()   { lfc_error "$*"; exit 1; }

lfc_ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

# ---------------------------------------------------------------------------
# Audit trail
#   lfc_audit <OK|FAIL|SKIP|DENY|START|END> <message>
# Appends a structured line to $LFC_AUDIT_LOG (created mode 0600).
# ---------------------------------------------------------------------------
lfc_audit() {
  local status="$1"; shift
  local line
  line="$(lfc_ts) | ${status} | stage=${LFC_STAGE:-init} | module=${LFC_MODULE:-none} | user=$(id -un 2>/dev/null || printf 'unknown') | $*"
  if [ -n "${LFC_AUDIT_LOG:-}" ]; then
    printf '%s\n' "$line" >>"$LFC_AUDIT_LOG" 2>/dev/null || true
  fi
  if [ "${LFC_VERBOSE:-0}" = "1" ]; then
    printf '[AUDIT] %s\n' "$line" >&2
  fi
}

# ---------------------------------------------------------------------------
# Command availability
# ---------------------------------------------------------------------------
lfc_have() { command -v "$1" >/dev/null 2>&1; }

# lfc_first <cmd> [cmd...]  -> prints path of first available command
lfc_first() {
  local c
  for c in "$@"; do
    if lfc_have "$c"; then command -v "$c"; return 0; fi
  done
  return 1
}

# lfc_capture <description> <cmd> [args...]
#   Runs a command, prints stdout on success. On failure records a SKIP
#   (missing command or non-zero exit) and returns non-zero. Never aborts.
lfc_capture() {
  local desc="$1"; shift
  if [ $# -eq 0 ]; then
    lfc_record_error "${LFC_MODULE:-unknown}" "$desc" "internal: no command given"
    return 1
  fi
  if ! lfc_have "$1"; then
    lfc_record_skip "${LFC_MODULE:-unknown}" "$desc" "command not available: $1"
    return 1
  fi
  local out rc
  if out=$("$@" 2>/dev/null); then
    printf '%s' "$out"
    return 0
  else
    rc=$?
    lfc_record_skip "${LFC_MODULE:-unknown}" "$desc" "command failed (rc=${rc}): $*"
    return "$rc"
  fi
}

# ---------------------------------------------------------------------------
# Skip / error registers (TSV fragments consumed by the report processor)
# ---------------------------------------------------------------------------
lfc_record_skip() {   # <module> <operation> <reason>
  [ -n "${LFC_RAW_DIR:-}" ] || return 0
  lfc_tsv_row "$LFC_RAW_DIR/skipped.tsv" "$1" "$2" "$3"
  lfc_audit "SKIP" "$1/$2: $3"
}

lfc_record_error() {  # <module> <operation> <message>
  [ -n "${LFC_RAW_DIR:-}" ] || return 0
  lfc_tsv_row "$LFC_RAW_DIR/errors.tsv" "$1" "$2" "$3"
  lfc_audit "FAIL" "$1/$2: $3"
  lfc_warn "$1/$2: $3"
}

# ---------------------------------------------------------------------------
# TSV fragment writers
#   Tab/newline/backslash are escaped so rows stay one-line and reversible.
#   The Python side (collector.fragments) unescapes them.
#
# PERFORMANCE: these helpers are intentionally fork-free (pure bash string
# operations + builtin printf). A single `$(...)` per row would spawn a
# subshell for every file inventoried and dominate runtime on large scans.
# ---------------------------------------------------------------------------
lfc_escape_into() {
  # Sets $LFC_ESCAPED to the escaped form of $1 (no subshell).
  local s="${1-}"
  s=${s//\\/\\\\}
  s=${s//$'\t'/\\t}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  LFC_ESCAPED="$s"
}

# lfc_tsv_header <file> <col> [col...]   (truncates/creates the file)
lfc_tsv_header() {
  local file="$1"; shift
  local out="" col first=1
  for col in "$@"; do
    [ "$first" -eq 1 ] || out+=$'\t'
    out+="${col}"
    first=0
  done
  printf '%s\n' "$out" >"$file"
}

# lfc_tsv_row <file> <val> [val...]      (appends one row, fork-free)
lfc_tsv_row() {
  local file="$1"; shift
  local out="" val first=1
  for val in "$@"; do
    [ "$first" -eq 1 ] || out+=$'\t'
    val=${val//\\/\\\\}
    val=${val//$'\t'/\\t}
    val=${val//$'\n'/\\n}
    val=${val//$'\r'/\\r}
    out+="$val"
    first=0
  done
  printf '%s\n' "$out" >>"$file"
}

# lfc_tsv_kv <file> <key> <value>        (appends a key/value row)
lfc_tsv_kv() { lfc_tsv_row "$1" "$2" "$3"; }

# ---------------------------------------------------------------------------
# Module enablement (reads CLI skip/only lists + config flags)
# ---------------------------------------------------------------------------
declare -a LFC_SKIP_MODULES=() LFC_ONLY_MODULES=()
declare -A LFC_CFG=()

lfc_module_enabled() {
  local m="$1" s
  for s in ${LFC_SKIP_MODULES[@]:-}; do
    [ "$m" = "$s" ] && return 1
  done
  if [ "${#LFC_ONLY_MODULES[@]}" -gt 0 ]; then
    local found=0 o
    for o in "${LFC_ONLY_MODULES[@]}"; do [ "$m" = "$o" ] && found=1; done
    [ "$found" = "1" ] || return 1
  fi
  [ "${LFC_CFG[collection.modules.$m]:-true}" = "true" ]
}

# ---------------------------------------------------------------------------
# Python interpreter resolution
#   Candidate order: explicit override, python3, python, py -3.
#   Each candidate is *validated* (some platforms ship a store stub named
#   python3 that always fails) before it is accepted.
# ---------------------------------------------------------------------------
lfc_python() {
  if [ -n "${LFC_PYTHON_BIN:-}" ]; then printf '%s' "$LFC_PYTHON_BIN"; return 0; fi
  local cand
  for cand in python3 python py; do
    if [ "$cand" = "py" ]; then
      if command -v py >/dev/null 2>&1 && py -3 -c 'import sys' >/dev/null 2>&1; then
        LFC_PYTHON_BIN="py -3"; printf '%s' "$LFC_PYTHON_BIN"; return 0
      fi
    elif command -v "$cand" >/dev/null 2>&1 && "$cand" -c 'import sys' >/dev/null 2>&1; then
      LFC_PYTHON_BIN="$cand"; printf '%s' "$LFC_PYTHON_BIN"; return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------
lfc_human_bytes() {  # <bytes> -> human readable (used in bash-side summaries)
  local b="${1:-0}"
  if lfc_have numfmt; then numfmt --to=iec --suffix=B "$b" 2>/dev/null && return 0; fi
  local units=(B KB MB GB TB) i=0
  while [ "$b" -ge 1024 ] && [ "$i" -lt 4 ]; do
    b=$((b / 1024)); i=$((i + 1))
  done
  printf '%s%s' "$b" "${units[$i]}"
}

# lfc_confirm <question>  -> 0 if user answered yes (interactive only)
lfc_confirm() {
  local q="$1" ans
  if [ "${LFC_NON_INTERACTIVE:-0}" = "1" ]; then
    return 1
  fi
  if [ ! -t 0 ]; then
    return 1
  fi
  printf '%s [y/N]: ' "$q" >&2
  IFS= read -r ans || return 1
  case "$ans" in
    y|Y|yes|YES|Yes) return 0 ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# Permission helpers
# ---------------------------------------------------------------------------
lfc_am_root() { [ "$(id -u 2>/dev/null || echo 1000)" = "0" ]; }

# Returns 0 when the process can already read privileged data.
lfc_is_elevated() {
  [ "${LFC_ELEVATED:-0}" = "1" ] || lfc_am_root
}
