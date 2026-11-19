#!/usr/bin/env bash
# =============================================================================
# lib/module_system.sh — Module A: System intelligence
# =============================================================================
# Fragments produced:
#   raw/system.general.tsv     key / value
#   raw/system.cpu.tsv         field / value
#   raw/system.memory.tsv      type / total / available / used / total_human
#   raw/system.storage.tsv     device / size / model / transport / rotational / type
#   raw/system.filesystems.tsv device / mount / fstype / size / used / avail / use%
# =============================================================================

lfc_module_system() {
  LFC_MODULE=system
  LFC_STAGE=collect
  lfc_audit "START" "system intelligence"

  local g="$LFC_RAW_DIR/system.general.tsv"
  local c="$LFC_RAW_DIR/system.cpu.tsv"
  local m="$LFC_RAW_DIR/system.memory.tsv"
  local s="$LFC_RAW_DIR/system.storage.tsv"
  local f="$LFC_RAW_DIR/system.filesystems.tsv"

  lfc_tsv_header "$g" key value
  lfc_tsv_header "$c" field value
  lfc_tsv_header "$m" type total_kb available_kb used_kb total_human
  lfc_tsv_header "$s" device size model transport rotational type
  lfc_tsv_header "$f" device mount fstype size used avail use_percent

  # --- identity ------------------------------------------------------------
  lfc_tsv_kv "$g" "hostname" "$(hostname 2>/dev/null || echo unknown)"
  lfc_tsv_kv "$g" "fqdn" "$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo unknown)"
  lfc_tsv_kv "$g" "distro_pretty" "${LFC_OS_PRETTY:-$(lfc_os_release_get PRETTY_NAME 2>/dev/null || echo unknown)}"
  lfc_tsv_kv "$g" "distro_id" "${LFC_OS_ID:-unknown}"
  lfc_tsv_kv "$g" "distro_version" "${LFC_OS_VERSION_ID:-unknown}"
  lfc_tsv_kv "$g" "kernel" "$(uname -r 2>/dev/null || echo unknown)"
  lfc_tsv_kv "$g" "kernel_release" "$(uname -v 2>/dev/null || echo unknown)"
  lfc_tsv_kv "$g" "arch" "$(uname -m 2>/dev/null || echo unknown)"
  lfc_tsv_kv "$g" "init_system" "${LFC_INIT_SYSTEM:-unknown}"
  lfc_tsv_kv "$g" "collected_at" "$(lfc_ts)"
  lfc_tsv_kv "$g" "collected_by" "$(id -un 2>/dev/null || echo unknown)"
  lfc_tsv_kv "$g" "elevated" "$([ "${LFC_ELEVATED:-0}" = 1 ] && echo yes || echo no)"
  lfc_tsv_kv "$g" "lfc_version" "$LFC_VERSION"

  local up_s=""
  if [ -r /proc/uptime ]; then
    up_s=$(awk '{printf "%d", $1}' /proc/uptime 2>/dev/null || echo "")
  elif lfc_have uptime; then
    up_s=$(lfc_capture "uptime" uptime 2>/dev/null | tr -dc '0-9.' | cut -d. -f1 || echo "")
  fi
  lfc_tsv_kv "$g" "uptime_seconds" "${up_s:-unknown}"

  # --- CPU -----------------------------------------------------------------
  local cpu_model="unknown" cpu_cores="unknown" cpu_mhz="" cpu_flags_present="no"
  if [ -r /proc/cpuinfo ]; then
    cpu_model=$(awk -F': ' '/^model name/ {print $2; exit}' /proc/cpuinfo 2>/dev/null || echo "")
    [ -n "$cpu_model" ] || cpu_model=$(awk -F': ' '/^Hardware/ {print $2; exit}' /proc/cpuinfo 2>/dev/null || echo "")
    [ -n "$cpu_model" ] || cpu_model="unknown"
    cpu_cores=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo "")
    cpu_mhz=$(awk -F': ' '/^cpu MHz/ {print $2; exit}' /proc/cpuinfo 2>/dev/null || echo "")
    grep -q '^flags' /proc/cpuinfo 2>/dev/null && cpu_flags_present="yes"
  elif lfc_have lscpu; then
    cpu_model=$(lfc_capture "lscpu model" lscpu 2>/dev/null | awk -F': ' '/^Model name/ {print $2; exit}' || echo "")
    cpu_cores=$(lfc_capture "lscpu cpus" lscpu 2>/dev/null | awk -F': ' '/^CPU\(s\)/ {print $2; exit}' || echo "")
  fi
  [ -n "$cpu_model" ] || cpu_model="unknown"
  [ -n "$cpu_cores" ] || cpu_cores="$(nproc 2>/dev/null || echo unknown)"

  lfc_tsv_kv "$c" "model" "$cpu_model"
  lfc_tsv_kv "$c" "logical_cpus" "$cpu_cores"
  lfc_tsv_kv "$c" "mhz" "${cpu_mhz:-unknown}"
  lfc_tsv_kv "$c" "flags_present" "$cpu_flags_present"
  if [ -r /sys/devices/system/cpu/online ]; then
    lfc_tsv_kv "$c" "online" "$(cat /sys/devices/system/cpu/online 2>/dev/null || echo unknown)"
  fi

  # --- Memory / swap (from /proc/meminfo — always present on Linux) --------
  if [ -r /proc/meminfo ]; then
    local mem_total mem_avail swap_total
    mem_total=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo "")
    mem_avail=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null || echo "")
    # Older kernels / minimal environments may lack MemAvailable.
    [ -n "$mem_avail" ] || mem_avail=$(awk '/^MemFree:/ {print $2}' /proc/meminfo 2>/dev/null || echo "")
    swap_total=$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo "")
    [ -n "$mem_total" ] || mem_total=0
    [ -n "$mem_avail" ] || mem_avail=0
    [ -n "$swap_total" ] || swap_total=0
    local mem_used=$(( mem_total - mem_avail ))
    [ "$mem_used" -lt 0 ] && mem_used=0
    lfc_tsv_row "$m" "memory" "$mem_total" "$mem_avail" "$mem_used" "$(lfc_human_bytes $((mem_total * 1024)))"
    lfc_tsv_row "$m" "swap" "$swap_total" "" "" "$(lfc_human_bytes $((swap_total * 1024)))"
  else
    lfc_record_skip "system" "memory" "/proc/meminfo not readable"
  fi

  # --- Storage devices -----------------------------------------------------
  if lfc_have lsblk; then
    local lsblk_out
    if lsblk_out=$(lsblk -dn -o NAME,SIZE,MODEL,TRAN,ROTA,TYPE 2>/dev/null); then
      local line dev size model trans rota type
      while IFS= read -r line; do
        [ -n "$line" ] || continue
        dev=$(awk '{print $1}' <<<"$line")
        size=$(awk '{print $2}' <<<"$line")
        # MODEL can contain spaces: reassemble fields 3..(n-2)
        type=$(awk '{print $NF}' <<<"$line")
        rota=$(awk '{print $(NF-1)}' <<<"$line")
        trans=$(awk '{print $(NF-2)}' <<<"$line")
        model=$(awk '{ for(i=3;i<=NF-3;i++) printf "%s ", $i }' <<<"$line" | sed 's/ *$//')
        [ -n "$model" ] || model="-"
        [ -n "$trans" ] || trans="-"
        lfc_tsv_row "$s" "$dev" "$size" "$model" "$trans" "$rota" "$type"
      done <<<"$lsblk_out"
    else
      lfc_record_skip "system" "storage(lsblk)" "lsblk failed"
    fi
  elif [ -r /proc/partitions ]; then
    local pdev pblocks
    while read -r _ pdev pblocks; do
      case "$pdev" in
        [0-9]*|loop*|ram*) continue ;;
      esac
      lfc_tsv_row "$s" "$pdev" "$((pblocks / 1024))MiB" "-" "-" "-" "disk"
    done < <(tail -n +3 /proc/partitions 2>/dev/null)
  else
    lfc_record_skip "system" "storage" "no lsblk and /proc/partitions unreadable"
  fi

  # --- Filesystems ---------------------------------------------------------
  local df_out=""
  if lfc_have df; then
    if df_out=$(df -PT 2>/dev/null); then
      local row dev mnt fst sz used av pc
      while IFS= read -r row; do
        case "$row" in
          Filesystem*) continue ;;
        esac
        dev=$(awk '{print $1}' <<<"$row")
        fst=$(awk '{print $2}' <<<"$row")
        sz=$(awk '{print $3}' <<<"$row")
        used=$(awk '{print $4}' <<<"$row")
        av=$(awk '{print $5}' <<<"$row")
        pc=$(awk '{print $6}' <<<"$row")
        mnt=$(awk '{ $1=$2=$3=$4=$5=$6=""; sub(/^ +/,""); print }' <<<"$row")
        case "$fst" in
          tmpfs|devtmpfs|squashfs|overlay|proc|sysfs|cgroup*|fuse.*) continue ;;
        esac
        lfc_tsv_row "$f" "$dev" "$mnt" "$fst" "$sz" "$used" "$av" "$pc"
      done <<<"$df_out"
    else
      lfc_record_skip "system" "filesystems(df)" "df failed"
    fi
  else
    lfc_record_skip "system" "filesystems" "df not available"
  fi

  # --- Hardware manufacturer / model ---------------------------------------
  local vendor="" product="" board=""
  local dmi
  for dmi in sys_vendor product_name board_vendor board_name; do
    [ -r "/sys/class/dmi/id/$dmi" ] || continue
    local v
    v=$(cat "/sys/class/dmi/id/$dmi" 2>/dev/null || echo "")
    case "$dmi" in
      sys_vendor|board_vendor) [ -z "$vendor" ] && vendor="$v" ;;
      product_name) product="$v" ;;
      board_name) board="$v" ;;
    esac
  done
  lfc_tsv_kv "$g" "hardware_vendor" "${vendor:-unknown}"
  lfc_tsv_kv "$g" "hardware_product" "${product:-unknown}"
  lfc_tsv_kv "$g" "hardware_board" "${board:-unknown}"

  if lfc_have hostnamectl; then
    local hc
    hc=$(hostnamectl 2>/dev/null || true)
    [ -n "$hc" ] && lfc_tsv_kv "$g" "hostnamectl" "$hc"
  fi

  lfc_audit "OK" "system intelligence collected"
}
