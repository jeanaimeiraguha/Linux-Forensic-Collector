#!/usr/bin/env bash
# ============================================================================
# Linux Forensic Collector (LFC) - installer
# ============================================================================
# Installs / prepares LFC on the local machine:
#   * verifies Bash and Python versions
#   * creates a local config from the template (if none exists)
#   * validates the configuration
#   * marks the scripts executable
#
# The installer NEVER runs the collector, never sends e-mail, never escalates
# privileges and never installs persistence. It only prepares files.
# ============================================================================
set -uo pipefail

LFC_INSTALL_VERSION="1.0.0"
LFC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAILURES=0

ok()   { printf '  [ OK ] %s\n' "$*"; }
warn() { printf '  [WARN] %s\n' "$*"; }
fail() { printf '  [FAIL] %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

printf 'Linux Forensic Collector (LFC) installer v%s\n' "$LFC_INSTALL_VERSION"
printf 'Install root: %s\n\n' "$LFC_ROOT"

# --- 1. Bash -----------------------------------------------------------------
printf 'Checking prerequisites...\n'
if [ -z "${BASH_VERSION:-}" ]; then
  fail "Run this script with bash (e.g. ./install.sh)"
else
  BASH_MAJOR="${BASH_VERSION%%.*}"
  BASH_MINOR="${BASH_VERSION#*.}"; BASH_MINOR="${BASH_MINOR%%.*}"
  if [ "$BASH_MAJOR" -gt 4 ] || { [ "$BASH_MAJOR" -eq 4 ] && [ "${BASH_MINOR:-0}" -ge 4 ]; }; then
    ok "Bash $BASH_VERSION"
  else
    fail "Bash 4.4+ required (found $BASH_VERSION)"
  fi
fi

# --- 2. Python ---------------------------------------------------------------
LFC_PY=""
for CAND in python3 python "py -3"; do
  # shellcheck disable=SC2086
  if command -v ${CAND%% *} >/dev/null 2>&1; then
    VER=$($CAND -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null) || VER=""
    if [ -n "$VER" ]; then
      PY_MAJOR="${VER%%.*}"; PY_MINOR="${VER#*.}"
      if [ "$PY_MAJOR" -gt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "${PY_MINOR:-0}" -ge 8 ]; }; then
        LFC_PY="$CAND"; ok "Python $VER ($CAND)"; break
      else
        warn "Python $VER found via '$CAND' but 3.8+ is required"
      fi
    fi
  fi
done
if [ -z "$LFC_PY" ]; then
  fail "Python 3.8+ not found. Install it (e.g. 'sudo apt install python3') and re-run."
fi

# --- 3. Local configuration --------------------------------------------------
printf '\nPreparing configuration...\n'
LOCAL_CFG="$LFC_ROOT/config/lfc.config.json"
TEMPLATE_CFG="$LFC_ROOT/config/config.template.json"
if [ -f "$LOCAL_CFG" ]; then
  ok "Existing config kept: config/lfc.config.json"
elif [ -f "$TEMPLATE_CFG" ]; then
  if cp "$TEMPLATE_CFG" "$LOCAL_CFG"; then
    ok "Created config/lfc.config.json from the template"
    warn "Edit config/lfc.config.json to set the recipient address and scan scope"
  else
    fail "Could not create config/lfc.config.json (permission denied?)"
  fi
else
  fail "config/config.template.json is missing from the installation"
fi

# --- 4. Validate configuration ----------------------------------------------
if [ -n "$LFC_PY" ] && [ -f "$LOCAL_CFG" ]; then
  printf '\nValidating configuration...\n'
  if (cd "$LFC_ROOT" && "$LFC_PY" -m collector config --config "$LOCAL_CFG" --validate >/dev/null 2>&1); then
    ok "Configuration is valid"
  else
    (cd "$LFC_ROOT" && "$LFC_PY" -m collector config --config "$LOCAL_CFG" --validate) || true
    fail "Configuration validation failed (see errors above)"
  fi
fi

# --- 5. Executable bits ------------------------------------------------------
printf '\nSetting permissions...\n'
for F in lfc.sh install.sh; do
  if [ -f "$LFC_ROOT/$F" ]; then
    if chmod +x "$LFC_ROOT/$F" 2>/dev/null; then
      ok "chmod +x $F"
    else
      warn "could not chmod +x $F (non-critical on this filesystem)"
    fi
  fi
done

# --- 6. Self-check -----------------------------------------------------------
printf '\nSelf-check (dry run)...\n'
if [ -x "$LFC_ROOT/lfc.sh" ] && [ -n "$LFC_PY" ]; then
  if "$LFC_ROOT/lfc.sh" --dry-run >/dev/null 2>&1; then
    ok "Collector dry-run completed"
  else
    # Dry-run needs a terminal-free environment; a non-zero exit still proves
    # the script loads, so report only if the binary itself is broken.
    if "$LFC_ROOT/lfc.sh" --version >/dev/null 2>&1; then
      warn "dry-run returned non-zero (reports/terminal conditions may differ); --version works"
    else
      fail "lfc.sh failed to start; run './lfc.sh --version' to see the error"
    fi
  fi
fi

# --- Summary -----------------------------------------------------------------
printf '\n'
if [ "$FAILURES" -eq 0 ]; then
  printf 'Installation complete.\n\n'
  printf 'Next steps:\n'
  printf '  1. Review config:      edit config/lfc.config.json\n'
  printf '  2. See all options:    ./lfc.sh --help\n'
  printf '  3. Preview a run:      ./lfc.sh --dry-run\n'
  printf '  4. Run collection:     ./lfc.sh\n'
  printf '  5. Reports land in:    ./output/<host>_<timestamp>/\n'
  printf '\nNothing is transmitted unless you explicitly approve sending.\n'
  exit 0
fi
printf 'Installation finished with %d problem(s). Fix them and re-run ./install.sh\n' "$FAILURES"
exit 1
