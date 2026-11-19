#!/usr/bin/env bash
# =============================================================================
# lib/detect.sh — Distribution, tool and capability detection
# =============================================================================
# Produces:
#   raw/detect.tsv   — platform key/values
#   raw/tools.tsv    — command availability matrix (with fallback notes)
# Sets globals used by modules:
#   LFC_OS_ID, LFC_OS_PRETTY, LFC_PKG_MGR, LFC_HAS_SYSTEMD, ...
# =============================================================================

# Read one KEY from /etc/os-release without sourcing (no code execution).
lfc_os_release_get() {
  local key="$1" file="${2:-/etc/os-release}" line value
  [ -r "$file" ] || return 1
  line=$(grep -E "^${key}=" "$file" 2>/dev/null | head -n 1) || return 1
  value="${line#*=}"
  value="${value%\"}"; value="${value#\"}"
  value="${value%\'}"; value="${value#\'}"
  printf '%s' "$value"
}

# ---------------------------------------------------------------------------
lfc_detect_platform() {
  LFC_MODULE=detect
  LFC_STAGE=detect
  lfc_audit "START" "platform detection"

  local raw="$LFC_RAW_DIR/detect.tsv"
  lfc_tsv_header "$raw" key value

  LFC_OS_PRETTY=$(lfc_os_release_get PRETTY_NAME 2>/dev/null || true)
  LFC_OS_ID=$(lfc_os_release_get ID 2>/dev/null || true)
  LFC_OS_VERSION_ID=$(lfc_os_release_get VERSION_ID 2>/dev/null || true)
  LFC_OS_ID_LIKE=$(lfc_os_release_get ID_LIKE 2>/dev/null || true)

  [ -n "$LFC_OS_PRETTY" ] || LFC_OS_PRETTY="$(uname -s 2>/dev/null || echo Unknown)"
  [ -n "$LFC_OS_ID" ] || LFC_OS_ID="unknown"

  local kernel arch hostname_s uptime_s
  kernel=$(uname -r 2>/dev/null || echo unknown)
  arch=$(uname -m 2>/dev/null || echo unknown)
  hostname_s=$(hostname 2>/dev/null || echo unknown)
  uptime_s=$(awk '{printf "%d", $1}' /proc/uptime 2>/dev/null || echo "")

  lfc_tsv_kv "$raw" "distro_pretty" "$LFC_OS_PRETTY"
  lfc_tsv_kv "$raw" "distro_id" "$LFC_OS_ID"
  lfc_tsv_kv "$raw" "distro_version_id" "$LFC_OS_VERSION_ID"
  lfc_tsv_kv "$raw" "distro_id_like" "$LFC_OS_ID_LIKE"
  lfc_tsv_kv "$raw" "kernel" "$kernel"
  lfc_tsv_kv "$raw" "arch" "$arch"
  lfc_tsv_kv "$raw" "hostname" "$hostname_s"
  lfc_tsv_kv "$raw" "uptime_seconds" "$uptime_s"
  lfc_tsv_kv "$raw" "detected_at" "$(lfc_ts)"
  lfc_tsv_kv "$raw" "lfc_version" "$LFC_VERSION"
  lfc_tsv_kv "$raw" "shell" "${BASH_VERSION:-unknown}"
  lfc_tsv_kv "$raw" "user" "$(id -un 2>/dev/null || echo unknown)"
  lfc_tsv_kv "$raw" "elevated" "$([ "${LFC_ELEVATED:-0}" = "1" ] && echo yes || echo no)"

  # --- package manager -----------------------------------------------------
  LFC_PKG_MGR=""
  if lfc_have apt-get; then LFC_PKG_MGR="apt"
  elif lfc_have dnf; then LFC_PKG_MGR="dnf"
  elif lfc_have pacman; then LFC_PKG_MGR="pacman"
  elif lfc_have zypper; then LFC_PKG_MGR="zypper"
  elif lfc_have yum; then LFC_PKG_MGR="yum"
  fi
  lfc_tsv_kv "$raw" "package_manager" "${LFC_PKG_MGR:-none}"

  # --- service manager -----------------------------------------------------
  LFC_HAS_SYSTEMD=0
  if lfc_have systemctl && [ -d /run/systemd/system ]; then
    LFC_HAS_SYSTEMD=1
  fi
  lfc_tsv_kv "$raw" "systemd" "$([ "$LFC_HAS_SYSTEMD" = 1 ] && echo yes || echo no)"

  # --- init system fallback ------------------------------------------------
  LFC_INIT_SYSTEM="unknown"
  if [ "$LFC_HAS_SYSTEMD" = 1 ]; then
    LFC_INIT_SYSTEM="systemd"
  elif [ -r /proc/1/comm ]; then
    LFC_INIT_SYSTEM=$(cat /proc/1/comm 2>/dev/null || echo unknown)
  fi
  lfc_tsv_kv "$raw" "init_system" "$LFC_INIT_SYSTEM"

  lfc_audit "OK" "platform=${LFC_OS_PRETTY} kernel=${kernel} pkg=${LFC_PKG_MGR:-none}"
}

# ---------------------------------------------------------------------------
# Capability matrix: for each command record availability + chosen fallback.
# ---------------------------------------------------------------------------
lfc_detect_tools() {
  LFC_MODULE=detect
  local out="$LFC_RAW_DIR/tools.tsv"
  lfc_tsv_header "$out" command available path fallback

  local spec cmd fallback available path
  # spec format: command:fallback-description
  local specs=(
    "ip:ifconfig"
    "ifconfig:none"
    "ss:netstat"
    "netstat:none"
    "resolvectl:read-/etc/resolv.conf"
    "nmcli:none"
    "ethtool:none"
    "lsblk:read-/proc/partitions"
    "df:none"
    "free:read-/proc/meminfo"
    "lscpu:read-/proc/cpuinfo"
    "uptime:read-/proc/uptime"
    "systemctl:none"
    "journalctl:none"
    "dpkg-query:none"
    "rpm:none"
    "pacman:none"
    "zypper:none"
    "ufw:none"
    "firewall-cmd:none"
    "nft:none"
    "iptables:none"
    "find:none"
    "stat:none"
    "numfmt:none"
    "timeout:none"
    "sha256sum:openssl-dgst-sha256"
    "tar:none"
    "gzip:none"
    "hostnamectl:none"
    "sensors:none"
    "smartctl:none"
    "awk:none"
    "sed:none"
    "grep:none"
  )

  for spec in "${specs[@]}"; do
    cmd="${spec%%:*}"
    fallback="${spec#*:}"
    if path=$(command -v "$cmd" 2>/dev/null); then
      available="yes"
    else
      available="no"
      path=""
    fi
    lfc_tsv_row "$out" "$cmd" "$available" "$path" "$fallback"
  done

  # Python is mandatory for report generation — verify it actually runs.
  local pybin
  if pybin=$(lfc_python); then
    lfc_tsv_row "$out" "python3" "yes" "$pybin" "none"
    LFC_PYTHON_BIN="$pybin"
  else
    lfc_tsv_row "$out" "python3" "no" "" "install python3 (>=3.8)"
    LFC_PYTHON_BIN=""
  fi

  lfc_audit "OK" "tool matrix written ($(wc -l <"$out" 2>/dev/null || echo 0) entries)"
}

# Convenience: require python early with a friendly, distro-specific message.
lfc_require_python() {
  if [ -n "${LFC_PYTHON_BIN:-}" ]; then return 0; fi
  local hint=""
  case "${LFC_PKG_MGR:-}" in
    apt)     hint="sudo apt-get install -y python3" ;;
    dnf)     hint="sudo dnf install -y python3" ;;
    yum)     hint="sudo yum install -y python3" ;;
    pacman)  hint="sudo pacman -S --noconfirm python" ;;
    zypper)  hint="sudo zypper install -y python3" ;;
    *)       hint="install Python 3.8 or newer with your package manager" ;;
  esac
  lfc_die "Python 3 is required for report generation. Run: ${hint}"
}

# ---------------------------------------------------------------------------
lfc_detect_all() {
  lfc_detect_platform
  lfc_detect_tools
}
