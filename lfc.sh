#!/usr/bin/env bash
# =============================================================================
# lfc.sh — Linux Forensic Collector (LFC) main entry point
# =============================================================================
# Workflow (see README.md):
#   1. Operator downloads this script and executes it EXPLICITLY.
#   2. LFC detects the distribution, tooling and required permissions.
#   3. Collection modules run only after scope approval.
#   4. Structured reports are generated for review.
#   5. Reports are transmitted ONLY after explicit operator approval.
#
# LFC never executes automatically, never escalates silently, never
# harvests credentials and never uploads anything without approval.
# =============================================================================
set -uo pipefail

LFC_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=lib/common.sh
. "$LFC_ROOT/lib/common.sh"
# shellcheck source=lib/detect.sh
. "$LFC_ROOT/lib/detect.sh"
# shellcheck source=lib/permissions.sh
. "$LFC_ROOT/lib/permissions.sh"
# shellcheck source=lib/module_system.sh
. "$LFC_ROOT/lib/module_system.sh"
# shellcheck source=lib/module_filesystem.sh
. "$LFC_ROOT/lib/module_filesystem.sh"
# shellcheck source=lib/module_media.sh
. "$LFC_ROOT/lib/module_media.sh"
# shellcheck source=lib/module_browser.sh
. "$LFC_ROOT/lib/module_browser.sh"
# shellcheck source=lib/module_network.sh
. "$LFC_ROOT/lib/module_network.sh"
# shellcheck source=lib/module_software.sh
. "$LFC_ROOT/lib/module_software.sh"
# shellcheck source=lib/delivery.sh
. "$LFC_ROOT/lib/delivery.sh"

# Make `python -m collector ...` work regardless of the caller's cwd.
export PYTHONPATH="$LFC_ROOT${PYTHONPATH:+:$PYTHONPATH}"

# ---------------------------------------------------------------------------
# Defaults (CLI flags override; config file overrides built-in defaults)
# ---------------------------------------------------------------------------
LFC_CONFIG=""
LFC_OUTPUT_BASE="./lfc_reports"
LFC_NON_INTERACTIVE=0
LFC_YES=0
LFC_APPROVE_SEND=0
LFC_NO_SEND=0
LFC_WANT_PRIVILEGE=0
LFC_APPROVE_ELEVATE=0
LFC_APPROVE_FILE_SCAN=0
LFC_DRY_RUN=0
LFC_VERBOSE=0
LFC_STARTED_AT=""
LFC_START_EPOCH=0

declare -a LFC_SCOPE_OVERRIDE=()
declare -a LFC_SKIP_MODULES=()
declare -a LFC_ONLY_MODULES=()
declare -A LFC_CFG=()

MODULE_ORDER=(system filesystem media browser network software)

usage() {
  cat <<EOF
${LFC_TOOL_NAME} v${LFC_VERSION}

Usage: ./lfc.sh [options]

Collection options:
  --config FILE          JSON configuration file
                         (default: config/lfc.config.json if present,
                          otherwise config/config.template.json)
  --scope PATH           Directory/file to inventory (repeatable;
                         overrides collection.scope_paths from config)
  --skip MODULE          Skip a module (repeatable:
                         system, filesystem, media, browser, network, software)
  --only MODULE          Run only the listed module (repeatable)
  --privileged           Request sudo for privileged metadata (asks first)
  --approve-file-scan    Pre-authorize file METADATA scanning of the scope
                         (required for non-interactive runs that scan files)
  --dry-run              Show the collection plan and exit

Delivery options:
  --approve-send         Pre-authorize SMTP transmission of the reports
  --no-send              Never transmit; generate reports locally only

General options:
  --output DIR           Base output directory (default: ./lfc_reports)
  --yes, --non-interactive
                         Do not prompt (still requires explicit approval
                         flags for file scanning and email transmission)
  --verbose              Print audit events to the console
  -h, --help             Show this help
  -V, --version          Show version

Environment (SMTP credentials — never stored in files):
  LFC_SMTP_USERNAME      SMTP login name
  LFC_SMTP_PASSWORD      SMTP password / app password

Security: no stealth execution, no credential harvesting, no persistence,
no hidden uploads. Reports are transmitted only after explicit approval.
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --config)
      [ $# -ge 2 ] || lfc_die "--config requires a value"
      LFC_CONFIG="$2"; shift 2 ;;
    --scope)
      [ $# -ge 2 ] || lfc_die "--scope requires a value"
      LFC_SCOPE_OVERRIDE+=("$2"); shift 2 ;;
    --skip)
      [ $# -ge 2 ] || lfc_die "--skip requires a module name"
      LFC_SKIP_MODULES+=("$2"); shift 2 ;;
    --only)
      [ $# -ge 2 ] || lfc_die "--only requires a module name"
      LFC_ONLY_MODULES+=("$2"); shift 2 ;;
    --output)
      [ $# -ge 2 ] || lfc_die "--output requires a value"
      LFC_OUTPUT_BASE="$2"; shift 2 ;;
    --privileged) LFC_WANT_PRIVILEGE=1; shift ;;
    --approve-elevate) LFC_APPROVE_ELEVATE=1; LFC_WANT_PRIVILEGE=1; shift ;;
    --approve-file-scan) LFC_APPROVE_FILE_SCAN=1; shift ;;
    --approve-send) LFC_APPROVE_SEND=1; shift ;;
    --no-send) LFC_NO_SEND=1; shift ;;
    --dry-run) LFC_DRY_RUN=1; shift ;;
    --yes|--non-interactive) LFC_YES=1; LFC_NON_INTERACTIVE=1; shift ;;
    --verbose) LFC_VERBOSE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    -V|--version) printf '%s v%s\n' "$LFC_TOOL_NAME" "$LFC_VERSION"; exit 0 ;;
    *) lfc_die "unknown option: $1 (use --help)" ;;
  esac
done

# Validate --skip/--only names early.
for m in "${LFC_SKIP_MODULES[@]:-}" "${LFC_ONLY_MODULES[@]:-}"; do
  [ -n "$m" ] || continue
  valid=0
  for known in "${MODULE_ORDER[@]}"; do [ "$m" = "$known" ] && valid=1; done
  [ "$valid" = "1" ] || lfc_die "unknown module: $m (valid: ${MODULE_ORDER[*]})"
done

# ---------------------------------------------------------------------------
# Configuration resolution
# ---------------------------------------------------------------------------
if [ -z "$LFC_CONFIG" ]; then
  if [ -f "$LFC_ROOT/config/lfc.config.json" ]; then
    LFC_CONFIG="$LFC_ROOT/config/lfc.config.json"
  else
    LFC_CONFIG="$LFC_ROOT/config/config.template.json"
  fi
fi
[ -f "$LFC_CONFIG" ] || lfc_die "config file not found: $LFC_CONFIG"

LFC_STAGE=init
lfc_log "$LFC_TOOL_NAME v$LFC_VERSION"
lfc_log "Config: $LFC_CONFIG"

LFC_PYTHON_BIN=$(lfc_python) || lfc_die \
  "Python 3 not found. Install it (e.g. sudo apt-get install -y python3) and re-run."
export LFC_PYTHON_BIN
lfc_log "Python: $LFC_PYTHON_BIN"

if ! "$LFC_PYTHON_BIN" -m collector config --config "$LFC_CONFIG" --validate >/dev/null 2>&1; then
  "$LFC_PYTHON_BIN" -m collector config --config "$LFC_CONFIG" --validate || true
  lfc_die "configuration validation failed (see errors above)"
fi

# Flatten config into LFC_CFG for bash-side reads.
# (strip CR defensively: some platforms emit CRLF on piped stdout)
while IFS=$'\t' read -r key val; do
  key=${key%$'\r'}
  val=${val%$'\r'}
  [ -n "$key" ] || continue
  LFC_CFG["$key"]="$val"
done < <("$LFC_PYTHON_BIN" -m collector config --config "$LFC_CONFIG" --flatten)

# Collection tuning knobs consumed by the scan modules.
LFC_LARGE_FILE_MB="${LFC_CFG[collection.large_file_threshold_mb]:-500}"
LFC_MAX_DEPTH="${LFC_CFG[collection.max_depth]:-10}"
LFC_MAX_FILES="${LFC_CFG[collection.max_files]:-100000}"
case "${LFC_CFG[collection.include_hidden_paths]:-false}" in
  true|1|yes) LFC_INCLUDE_HIDDEN=1 ;;
  *) LFC_INCLUDE_HIDDEN=0 ;;
esac
case "${LFC_CFG[collection.cross_filesystems]:-false}" in
  true|1|yes) LFC_CROSS_FS=1 ;;
  *) LFC_CROSS_FS=0 ;;
esac

# ---------------------------------------------------------------------------
# Module enablement (lfc_module_enabled lives in lib/common.sh)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Scope resolution
# ---------------------------------------------------------------------------
declare -a LFC_SCOPE_PATHS=()
if [ ${#LFC_SCOPE_OVERRIDE[@]} -gt 0 ]; then
  LFC_SCOPE_PATHS=("${LFC_SCOPE_OVERRIDE[@]}")
else
  while IFS= read -r p; do
    p=${p%$'\r'}
    [ -n "$p" ] && LFC_SCOPE_PATHS+=("$p")
  done < <("$LFC_PYTHON_BIN" -m collector config --config "$LFC_CONFIG" \
           --get-array collection.scope_paths)
fi

# ---------------------------------------------------------------------------
# Dry run: show the plan and exit before touching anything
# ---------------------------------------------------------------------------
if [ "$LFC_DRY_RUN" = "1" ]; then
  printf '\nLFC collection plan (dry run — nothing was executed)\n'
  printf '  Config   : %s\n' "$LFC_CONFIG"
  printf '  Output   : %s\n' "$LFC_OUTPUT_BASE"
  printf '  Scope    : %s\n' "${LFC_SCOPE_PATHS[*]:-<none>}"
  printf '  Modules  :'
  for m in "${MODULE_ORDER[@]}"; do
    lfc_module_enabled "$m" && printf ' %s' "$m"
  done
  printf '\n  Privileged ops : %s\n' "$([ "$LFC_WANT_PRIVILEGE" = 1 ] && echo 'requested (--privileged)' || echo 'not requested')"
  printf '  Email send     : %s\n' "$([ "$LFC_APPROVE_SEND" = 1 ] && echo 'pre-approved (--approve-send)' || echo 'requires interactive approval')"
  printf '  File scan      : %s\n' "$([ "$LFC_APPROVE_FILE_SCAN" = 1 ] && echo 'pre-approved (--approve-file-scan)' || echo 'requires approval')"
  printf '\nRe-run without --dry-run to start collection.\n\n'
  exit 0
fi

# ---------------------------------------------------------------------------
# Output directory + audit log
# ---------------------------------------------------------------------------
LFC_STAGE=setup
HOST_SAFE=$(hostname 2>/dev/null | tr -c 'A-Za-z0-9._-' '_' || echo host)
[ -n "$HOST_SAFE" ] || HOST_SAFE="host"
STAMP=$(date -u '+%Y%m%dT%H%M%SZ')
LFC_OUTPUT_DIR="$LFC_OUTPUT_BASE/${HOST_SAFE}_${STAMP}"
LFC_RAW_DIR="$LFC_OUTPUT_DIR/raw"
LFC_AUDIT_LOG="$LFC_OUTPUT_DIR/audit.log"

mkdir -p "$LFC_RAW_DIR" || lfc_die "cannot create output directory: $LFC_OUTPUT_DIR"
chmod 700 "$LFC_OUTPUT_DIR" 2>/dev/null || true
chmod 600 "$LFC_AUDIT_LOG" 2>/dev/null || true
touch "$LFC_AUDIT_LOG" 2>/dev/null || true
chmod 600 "$LFC_AUDIT_LOG" 2>/dev/null || true

lfc_tsv_header "$LFC_RAW_DIR/skipped.tsv" module operation reason
lfc_tsv_header "$LFC_RAW_DIR/errors.tsv" module operation message

lfc_audit "START" "lfc run begin version=${LFC_VERSION} config=${LFC_CONFIG}"
lfc_log "Output directory: $LFC_OUTPUT_DIR"

# ---------------------------------------------------------------------------
# Interruption handling — record, never hide
# ---------------------------------------------------------------------------
on_interrupt() {
  LFC_STAGE=interrupted
  lfc_audit "FAIL" "run interrupted by operator (SIGINT/SIGTERM)"
  lfc_warn "Interrupted. Partial reports (if any) remain in: $LFC_OUTPUT_DIR"
  exit 130
}
trap on_interrupt INT TERM

# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
lfc_detect_all
lfc_require_python

# ---------------------------------------------------------------------------
# Privileged metadata (opt-in only)
# ---------------------------------------------------------------------------
LFC_STAGE=permissions
LFC_ELEVATED=0
lfc_request_elevation || true

# ---------------------------------------------------------------------------
# Scope approval for file metadata scanning
# ---------------------------------------------------------------------------
LFC_STAGE=approval
NEED_FILE_SCAN=0
if lfc_module_enabled filesystem || lfc_module_enabled media; then
  NEED_FILE_SCAN=1
fi

if [ "$NEED_FILE_SCAN" = "1" ] && [ "$LFC_APPROVE_FILE_SCAN" != "1" ]; then
  printf '\n' >&2
  lfc_log "File METADATA scan requested for the following scope:"
  for p in "${LFC_SCOPE_PATHS[@]:-}"; do
    [ -n "$p" ] && printf '    - %s\n' "$p" >&2
  done
  lfc_log "Only paths, sizes and timestamps are recorded — file CONTENTS are never read."
  if lfc_confirm "Authorize this file metadata scan?"; then
    LFC_APPROVE_FILE_SCAN=1
    lfc_audit "OK" "operator authorized file metadata scan"
  else
    lfc_audit "DENY" "operator declined file metadata scan"
    LFC_SKIP_MODULES+=("filesystem" "media")
    NEED_FILE_SCAN=0
    lfc_warn "Filesystem and media modules will be skipped."
  fi
fi

if [ "$NEED_FILE_SCAN" = "1" ] && [ "$LFC_APPROVE_FILE_SCAN" != "1" ]; then
  # Non-interactive run without approval: skip scanning (privacy first).
  lfc_audit "DENY" "no file scan approval available (non-interactive)"
  LFC_SKIP_MODULES+=("filesystem" "media")
  NEED_FILE_SCAN=0
  lfc_warn "Non-interactive run without --approve-file-scan: filesystem/media skipped."
fi

# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------
LFC_STAGE=collect
LFC_START_EPOCH=$(date +%s 2>/dev/null || echo 0)
LFC_STARTED_AT=$(lfc_ts)

declare -a LFC_MODULES_RUN=()
for m in "${MODULE_ORDER[@]}"; do
  if ! lfc_module_enabled "$m"; then
    lfc_audit "SKIP" "module not run: $m"
    continue
  fi
  lfc_log "Running module: $m"
  case "$m" in
    system)     lfc_module_system ;;
    filesystem) lfc_module_filesystem ;;
    media)      lfc_module_media ;;
    browser)    lfc_module_browser ;;
    network)    lfc_module_network ;;
    software)   lfc_module_software ;;
  esac
  LFC_MODULES_RUN+=("$m")
  lfc_refresh_elevation || true
done

LFC_END_EPOCH=$(date +%s 2>/dev/null || echo 0)
DURATION=$(( LFC_END_EPOCH - LFC_START_EPOCH ))
[ "$DURATION" -ge 0 ] || DURATION=0

if [ ${#LFC_MODULES_RUN[@]} -eq 0 ]; then
  lfc_die "no modules were run (check --skip/--only and configuration)"
fi

# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
LFC_STAGE=report
LFC_MODULE=report
lfc_log "Generating reports..."
report_cmd=(
  "$LFC_PYTHON_BIN" -m collector report
  --raw "$LFC_RAW_DIR"
  --out "$LFC_OUTPUT_DIR"
  --config "$LFC_CONFIG"
  --modules "$(IFS=,; echo "${LFC_MODULES_RUN[*]}")"
  --duration "$DURATION"
  --started-at "$LFC_STARTED_AT"
)
for p in "${LFC_SCOPE_PATHS[@]:-}"; do
  [ -n "$p" ] && report_cmd+=(--scope "$p")
done

if ! "${report_cmd[@]}"; then
  lfc_die "report generation failed"
fi

# Reports contain sensitive system detail — lock them down.
chmod 600 "$LFC_OUTPUT_DIR"/system_report.* 2>/dev/null || true
chmod 600 "$LFC_OUTPUT_DIR"/*_inventory.csv 2>/dev/null || true

lfc_audit "OK" "reports generated in ${LFC_OUTPUT_DIR} (modules: ${LFC_MODULES_RUN[*]})"

# ---------------------------------------------------------------------------
# Review + optional approved delivery
# ---------------------------------------------------------------------------
LFC_STAGE=review
LFC_MODULE=review
printf '\n' >&2
lfc_log "Reports are ready for review:"
printf '    %s/system_report.html\n' "$LFC_OUTPUT_DIR" >&2
printf '    %s/system_report.json\n' "$LFC_OUTPUT_DIR" >&2
printf '    %s/system_report.txt\n' "$LFC_OUTPUT_DIR" >&2
printf '    %s/filesystem_inventory.csv\n' "$LFC_OUTPUT_DIR" >&2
printf '    %s/media_inventory.csv\n' "$LFC_OUTPUT_DIR" >&2
printf '    %s/audit.log\n' "$LFC_OUTPUT_DIR" >&2
printf '\n' >&2

LFC_STAGE=delivery
LFC_MODULE=smtp
if [ "$LFC_NO_SEND" = "1" ]; then
  lfc_audit "OK" "delivery skipped by operator (--no-send)"
  lfc_log "Email transmission disabled (--no-send). Reports stored locally."
elif [ "${LFC_CFG[smtp.enabled]:-false}" != "true" ]; then
  lfc_audit "OK" "delivery skipped: smtp.enabled=false in configuration"
  lfc_log "SMTP delivery is disabled in the configuration; reports stored locally."
  lfc_log "To enable delivery, set smtp.enabled=true and configure SMTP settings."
else
  RECIPIENT=$(lfc_delivery_recipient)
  lfc_log "SMTP delivery preview:"
  lfc_delivery_preview || true
  printf '\n' >&2

  APPROVED=0
  if [ "$LFC_APPROVE_SEND" = "1" ]; then
    APPROVED=1
    lfc_audit "OK" "send pre-approved via --approve-send"
  elif [ "$LFC_NON_INTERACTIVE" = "1" ]; then
    lfc_audit "DENY" "non-interactive run: transmission not approved"
    lfc_warn "Non-interactive run: reports NOT transmitted (pass --approve-send to authorize)."
  elif lfc_confirm "Transmit the approved report bundle to ${RECIPIENT}?"; then
    APPROVED=1
    lfc_audit "OK" "operator approved transmission"
  else
    lfc_audit "DENY" "operator declined transmission"
    lfc_log "Transmission declined. Reports remain local."
  fi

  if [ "$APPROVED" = "1" ]; then
    SEND_RC=0
    lfc_delivery_send 1 || SEND_RC=$?
    case "$SEND_RC" in
      0) lfc_log "Report bundle delivered successfully." ;;
      4) lfc_error "Bundle exceeds smtp.max_attachment_mb — reduce scope or raise the limit." ;;
      5) lfc_error "SMTP transmission failed — check credentials/network (audit.log has details)." ;;
      *) lfc_error "Delivery failed (exit code ${SEND_RC})." ;;
    esac
  fi
fi

# ---------------------------------------------------------------------------
# Finalize
# ---------------------------------------------------------------------------
LFC_STAGE=finalize
LFC_MODULE=main
lfc_audit "END" "run complete modules=${LFC_MODULES_RUN[*]} duration=${DURATION}s output=${LFC_OUTPUT_DIR}"
printf '\n' >&2
lfc_log "Audit log: $LFC_AUDIT_LOG"
lfc_log "Done. Review the reports before sharing them outside this machine."
exit 0
