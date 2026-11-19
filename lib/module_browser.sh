#!/usr/bin/env bash
# =============================================================================
# lib/module_browser.sh — Module D: Browser security audit
# =============================================================================
# Produces:
#   raw/browser.installs.tsv   browser / installed / binary / version /
#                              package_version / source
#   raw/browser.profiles.tsv   browser / profile_name / profile_path / prefs_file
#
# SECURITY BOUNDARY (enforced here AND in collector/browser_prefs.py):
#   * Only installation facts, versions, profile locations and a small
#     allowlist of non-sensitive security preferences are inspected.
#   * Password stores, cookies, session tokens, private keys, autofill data,
#     history, bookmarks and Google account material are NEVER opened,
#     decrypted, exported or transmitted.
#   * Prefs file contents are not parsed in bash; the report processor reads
#     only allowlisted keys (see ALLOWED_PREF_KEYS in browser_prefs.py).
# =============================================================================

# lfc_probe_browser <name> <space-separated-binary-candidates> <profile-root>...
lfc_probe_browser() {
  local name="$1"; shift
  local candidates="$1"; shift
  local -a profile_roots=("$@")

  local inst="$LFC_RAW_DIR/browser.installs.tsv"
  local prof="$LFC_RAW_DIR/browser.profiles.tsv"

  local bin="" c
  for c in $candidates; do
    if bin=$(command -v "$c" 2>/dev/null); then
      break
    fi
    # Common non-PATH locations
    local alt
    for alt in "/usr/bin/$c" "/usr/local/bin/$c" "/opt/google/chrome/$c" \
               "/snap/bin/$c" "/usr/lib/chromium/$c"; do
      if [ -x "$alt" ]; then bin="$alt"; break; fi
    done
    [ -n "$bin" ] && break
  done

  local installed="no" version="" source="absent"
  if [ -n "$bin" ]; then
    installed="yes"
    source="binary"
    if lfc_have timeout; then
      version=$(timeout 10 "$bin" --version 2>/dev/null | head -n 1 || echo "")
    else
      version=$("$bin" --version 2>/dev/null | head -n 1 || echo "")
    fi
    [ -n "$version" ] || version="unknown"
  fi

  # Package-manager lookup (version only — never package contents).
  local pkg_version="" pkg=""
  case "$name" in
    chrome)  pkg="google-chrome-stable google-chrome" ;;
    chromium) pkg="chromium chromium-browser" ;;
    firefox) pkg="firefox firefox-esr" ;;
    edge)    pkg="microsoft-edge-stable microsoft-edge" ;;
  esac
  local p
  for p in $pkg; do
    [ -n "$pkg_version" ] && break
    case "${LFC_PKG_MGR:-}" in
      apt)
        if lfc_have dpkg-query; then
          pkg_version=$(dpkg-query -W -f='${Version}' "$p" 2>/dev/null || true)
        fi ;;
      dnf|yum)
        if lfc_have rpm; then
          pkg_version=$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$p" 2>/dev/null || true)
        fi ;;
      pacman)
        if lfc_have pacman; then
          pkg_version=$(pacman -Q "$p" 2>/dev/null | awk '{print $2}' || true)
        fi ;;
      zypper)
        if lfc_have rpm; then
          pkg_version=$(rpm -q --qf '%{VERSION}-%{RELEASE}' "$p" 2>/dev/null || true)
        fi ;;
    esac
    # rpm/dpkg return multi-line errors on miss — keep only a clean version
    case "$pkg_version" in
      *$'\n'*|"") pkg_version="" ;;
      *not\ installed*|*"no packages found"*) pkg_version="" ;;
    esac
    [ -n "$pkg_version" ] && source="package"
  done

  if [ "$installed" = "no" ] && [ -n "$pkg_version" ]; then
    installed="yes"
  fi

  lfc_tsv_row "$inst" "$name" "$installed" "${bin:-}" "${version:-}" \
    "${pkg_version:-}" "$source"

  # --- profile locations (names/paths only, no content access) -------------
  local root child prefs pname count=0
  for root in "${profile_roots[@]}"; do
    [ -d "$root" ] || continue
    lfc_audit "OK" "browser profile root present: $name -> $root"
    for child in "$root"/*/; do
      [ -d "$child" ] || continue
      count=$((count + 1))
      [ "$count" -gt 50 ] && break
      pname=$(basename "${child%/}")
      prefs=""
      if [ -f "${child}Preferences" ]; then
        prefs="${child}Preferences"
      elif [ -f "${child}prefs.js" ]; then
        prefs="${child}prefs.js"
      fi
      lfc_tsv_row "$prof" "$name" "$pname" "${child%/}" "$prefs"
    done
    # Firefox-style root that stores prefs directly under the root
    if [ -f "$root/prefs.js" ]; then
      lfc_tsv_row "$prof" "$name" "(root)" "${root%/}" "$root/prefs.js"
    fi
  done

  lfc_audit "OK" "browser probe: $name installed=$installed version=${version:-n/a}"
}

# ---------------------------------------------------------------------------
lfc_module_browser() {
  LFC_MODULE=browser
  LFC_STAGE=collect
  lfc_audit "START" "browser security audit (no credential access)"

  local inst="$LFC_RAW_DIR/browser.installs.tsv"
  local prof="$LFC_RAW_DIR/browser.profiles.tsv"
  lfc_tsv_header "$inst" browser installed binary version package_version source
  lfc_tsv_header "$prof" browser profile_name profile_path prefs_file

  local home="${HOME:-/root}"

  lfc_probe_browser chrome \
    "google-chrome google-chrome-stable google-chrome-beta" \
    "$home/.config/google-chrome" \
    "$home/.var/app/com.google.Chrome/.config/google-chrome"

  lfc_probe_browser chromium \
    "chromium chromium-browser" \
    "$home/.config/chromium" \
    "$home/.var/app/org.chromium.Chromium/.config/chromium"

  lfc_probe_browser firefox \
    "firefox firefox-esr" \
    "$home/.mozilla/firefox" \
    "$home/snap/firefox/common/.mozilla/firefox" \
    "$home/.var/app/org.mozilla.firefox/.mozilla/firefox"

  lfc_probe_browser edge \
    "microsoft-edge microsoft-edge-stable microsoft-edge-beta" \
    "$home/.config/microsoft-edge" \
    "$home/.var/app/com.microsoft.Edge/.config/microsoft-edge"

  # Explicit record of what was NOT accessed (surfaced in the report).
  local not_accessed="$LFC_RAW_DIR/browser.not_accessed.tsv"
  lfc_tsv_header "$not_accessed" item status
  local item
  for item in "saved passwords / logins" "cookies" "session tokens" \
              "autofill / form data" "browsing history" "bookmarks" \
              "private keys / certificates" "Google account credentials" \
              "payment methods"; do
    lfc_tsv_row "$not_accessed" "$item" "NOT ACCESSED"
  done

  lfc_audit "OK" "browser audit complete (credentials untouched)"
}
