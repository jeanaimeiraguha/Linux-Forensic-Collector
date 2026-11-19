#!/usr/bin/env bash
# =============================================================================
# lib/delivery.sh — Approved SMTP delivery of generated reports
# =============================================================================
# HARD RULES:
#   * Reports are NEVER transmitted without explicit operator approval.
#     Approval = interactive "y" answer OR --approve-send on the CLI.
#   * SMTP credentials come exclusively from environment variables named in
#     the config (password_env / username_env). No credentials are stored
#     in files, scripts or the repository.
#   * Attachment size is validated BEFORE any network connection is opened.
# =============================================================================
# Exit codes from `python -m collector send`:
#   0 delivered | 2 not approved | 3 configuration error
#   4 attachment too large | 5 SMTP transmission failure
# =============================================================================

lfc_delivery_enabled() {
  [ -n "${LFC_CONFIG:-}" ] || return 1
  local enabled
  enabled=$("$LFC_PYTHON_BIN" -m collector config --config "$LFC_CONFIG" \
            --get smtp.enabled 2>/dev/null | tr -d '\r')
  [ "$enabled" = "true" ]
}

lfc_delivery_recipient() {
  "$LFC_PYTHON_BIN" -m collector config --config "$LFC_CONFIG" \
    --get smtp.to_addr 2>/dev/null | tr -d '\r'
}

# Show what would be sent (recipient, subject, size) without transmitting.
lfc_delivery_preview() {
  LFC_STAGE=delivery
  "$LFC_PYTHON_BIN" -m collector send \
    --config "$LFC_CONFIG" \
    --reports "$LFC_OUTPUT_DIR" \
    --raw "$LFC_RAW_DIR" \
    --preview
  return $?
}

# lfc_delivery_send <approved:0|1>
lfc_delivery_send() {
  local approved="$1"
  LFC_STAGE=delivery
  lfc_audit "START" "email delivery requested (approved=${approved})"

  if [ "$approved" = "1" ]; then
    lfc_audit "OK" "operator approved report transmission"
  else
    lfc_audit "DENY" "transmission attempted without approval"
    lfc_warn "Report transmission requires explicit approval."
    return 2
  fi

  local rc=0
  "$LFC_PYTHON_BIN" -m collector send \
    --config "$LFC_CONFIG" \
    --reports "$LFC_OUTPUT_DIR" \
    --raw "$LFC_RAW_DIR" \
    --approved
  rc=$?

  case "$rc" in
    0) lfc_audit "OK" "reports delivered by SMTP" ;;
    2) lfc_audit "DENY" "send refused: approval flag missing" ;;
    3) lfc_audit "FAIL" "send refused: SMTP configuration error" ;;
    4) lfc_audit "FAIL" "send refused: attachment exceeds configured size limit" ;;
    5) lfc_audit "FAIL" "SMTP transmission failed (see report errors)" ;;
    *) lfc_audit "FAIL" "send failed with unexpected rc=${rc}" ;;
  esac
  return "$rc"
}
