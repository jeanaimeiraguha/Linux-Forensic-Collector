#!/usr/bin/env bash
# =============================================================================
# lib/module_software.sh — Module F: Installed software & services audit
# =============================================================================
# Produces:
#   raw/software.managers.tsv   manager / available / path
#   raw/software.packages.tsv   manager / name / version
#   raw/software.services.tsv   unit / state
#
# Only package names/versions and service states are recorded. Package
# contents are never downloaded, inspected or executed.
# =============================================================================

lfc_module_software() {
  LFC_MODULE=software
  LFC_STAGE=collect
  lfc_audit "START" "installed software audit"

  local mgrs="$LFC_RAW_DIR/software.managers.tsv"
  local pkgs="$LFC_RAW_DIR/software.packages.tsv"
  local svcs="$LFC_RAW_DIR/software.services.tsv"
  lfc_tsv_header "$mgrs" manager available path
  lfc_tsv_header "$pkgs" manager name version
  lfc_tsv_header "$svcs" unit state

  # --- package managers ----------------------------------------------------
  local m path
  for m in apt dpkg dnf yum pacman zypper; do
    if path=$(command -v "$m" 2>/dev/null); then
      lfc_tsv_row "$mgrs" "$m" "yes" "$path"
    else
      lfc_tsv_row "$mgrs" "$m" "no" ""
    fi
  done

  # --- package inventory ---------------------------------------------------
  local count=0
  case "${LFC_PKG_MGR:-}" in
    apt)
      if lfc_have dpkg-query; then
        local out
        if out=$(dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null); then
          while IFS=$'\t' read -r name ver; do
            [ -n "$name" ] || continue
            lfc_tsv_row "$pkgs" "dpkg" "$name" "${ver:-unknown}"
            count=$((count + 1))
          done <<<"$out"
        else
          lfc_record_error "software" "packages(dpkg)" "dpkg-query failed"
        fi
      fi
      ;;
    dnf|yum)
      if lfc_have rpm; then
        local out2
        if out2=$(rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null | sort); then
          while IFS=$'\t' read -r name ver; do
            [ -n "$name" ] || continue
            lfc_tsv_row "$pkgs" "rpm" "$name" "${ver:-unknown}"
            count=$((count + 1))
          done <<<"$out2"
        else
          lfc_record_error "software" "packages(rpm)" "rpm query failed"
        fi
      fi
      ;;
    pacman)
      if lfc_have pacman; then
        local out3
        if out3=$(pacman -Q 2>/dev/null); then
          while read -r name ver; do
            [ -n "$name" ] || continue
            lfc_tsv_row "$pkgs" "pacman" "$name" "${ver:-unknown}"
            count=$((count + 1))
          done <<<"$out3"
        else
          lfc_record_error "software" "packages(pacman)" "pacman query failed"
        fi
      fi
      ;;
    zypper)
      if lfc_have rpm; then
        local out4
        if out4=$(rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null | sort); then
          while IFS=$'\t' read -r name ver; do
            [ -n "$name" ] || continue
            lfc_tsv_row "$pkgs" "rpm" "$name" "${ver:-unknown}"
            count=$((count + 1))
          done <<<"$out4"
        else
          lfc_record_error "software" "packages(rpm)" "rpm query failed"
        fi
      fi
      ;;
    *)
      lfc_record_skip "software" "packages" "no supported package manager detected"
      ;;
  esac

  # --- services ------------------------------------------------------------
  if [ "${LFC_HAS_SYSTEMD:-0}" = "1" ] && lfc_have systemctl; then
    local units
    # Enabled at boot
    if units=$(systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager 2>/dev/null); then
      local u
      while read -r u _; do
        [ -n "$u" ] || continue
        lfc_tsv_row "$svcs" "$u" "enabled"
      done <<<"$units"
    else
      lfc_record_skip "software" "services(enabled)" "systemctl list-unit-files failed"
    fi
    # Currently running
    if units=$(systemctl list-units --type=service --state=running --no-legend --no-pager --all 2>/dev/null); then
      local u2 loaded active rest
      while read -r u2 loaded active rest; do
        [ -n "$u2" ] || continue
        lfc_tsv_row "$svcs" "$u2" "running"
      done <<<"$units"
    else
      lfc_record_skip "software" "services(running)" "systemctl list-units failed"
    fi
  else
    lfc_record_skip "software" "services" "systemd not detected; service enumeration unavailable"
  fi

  local sum="$LFC_RAW_DIR/software.summary.tsv"
  if [ ! -f "$sum" ]; then
    lfc_tsv_header "$sum" metric value
  fi
  lfc_tsv_kv "$sum" "packages_listed" "$count"

  lfc_audit "OK" "software audit: ${count} packages, manager=${LFC_PKG_MGR:-none}"
}
