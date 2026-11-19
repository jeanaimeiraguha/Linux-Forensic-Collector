#!/usr/bin/env bash
# =============================================================================
# lib/permissions.sh — Explicit, opt-in privilege handling
# =============================================================================
# Policy (see SECURITY.md):
#   * LFC NEVER escalates privileges silently.
#   * Elevation requires BOTH the --privileged flag AND an interactive
#     confirmation (or --approve-elevate for scripted runs the operator
#     has already authorised).
#   * When elevation is unavailable, the affected operation is recorded as
#     SKIPPED in the report and collection continues.
# =============================================================================

# Returns 0 when sudo credentials are already cached (non-interactive probe).
lfc_sudo_cached() {
  lfc_have sudo || return 1
  sudo -n true >/dev/null 2>&1
}

# Ask for sudo interactively. Never runs without explicit confirmation.
lfc_request_elevation() {
  if lfc_am_root; then
    LFC_ELEVATED=1
    lfc_audit "OK" "already running as root"
    return 0
  fi

  if [ "${LFC_WANT_PRIVILEGE:-0}" != "1" ]; then
    LFC_ELEVATED=0
    lfc_audit "DENY" "elevation not requested (pass --privileged to allow)"
    return 1
  fi

  if lfc_sudo_cached; then
    LFC_ELEVATED=1
    lfc_audit "OK" "using cached sudo credentials (pre-authorised)"
    return 0
  fi

  if ! lfc_have sudo; then
    LFC_ELEVATED=0
    lfc_record_skip "permissions" "elevation" "sudo is not installed"
    return 1
  fi

  # Explicit human confirmation before anything privileged happens.
  if [ "${LFC_APPROVE_ELEVATE:-0}" != "1" ]; then
    if ! lfc_confirm "LFC needs root for privileged metadata (e.g. process names in ss). Authorize 'sudo -v' now?"; then
      LFC_ELEVATED=0
      lfc_audit "DENY" "user declined sudo authorization"
      lfc_record_skip "permissions" "elevation" "user declined sudo authorization"
      return 1
    fi
  fi

  lfc_log "Requesting sudo credentials (authorized by operator)..."
  if sudo -v; then
    LFC_ELEVATED=1
    lfc_audit "OK" "sudo authorization granted"
    return 0
  fi

  LFC_ELEVATED=0
  lfc_audit "FAIL" "sudo authorization failed"
  lfc_record_error "permissions" "elevation" "sudo authorization failed"
  return 1
}

# Refresh cached sudo credentials during long runs (best effort).
lfc_refresh_elevation() {
  [ "${LFC_ELEVATED:-0}" = "1" ] || return 0
  lfc_am_root && return 0
  sudo -n true >/dev/null 2>&1 || sudo -v >/dev/null 2>&1 || {
    LFC_ELEVATED=0
    lfc_record_skip "permissions" "elevation-refresh" "sudo credentials expired"
    return 1
  }
}
