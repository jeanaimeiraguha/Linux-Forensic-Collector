#!/usr/bin/env bash
# =============================================================================
# lib/module_network.sh — Module E: Network audit
# =============================================================================
# Produces (metadata only):
#   raw/network.interfaces.tsv   iface / state / flags / mtu / operstate
#   raw/network.addresses.tsv    iface / family / scope / address
#   raw/network.routes.tsv       destination / gateway / device / protocol
#   raw/network.dns.tsv          source / server
#   raw/network.connections.tsv  protocol / state / local / peer / process
#   raw/network.firewall.tsv     backend / status / detail
#   raw/network.adapters.tsv     iface / driver / version / firmware
#
# EXCLUSIONS (hard policy): no packet capture, no sniffing, no traffic
# interception, no credential capture. Only configuration and connection
# METADATA are recorded.
#
# PERFORMANCE: per-row parsing is fork-free (bash builtins only) — no awk/
# grep subshells inside loops.
# =============================================================================

lfc_module_network() {
  LFC_MODULE=network
  LFC_STAGE=collect
  lfc_audit "START" "network audit (metadata only, no packet capture)"

  local ifc="$LFC_RAW_DIR/network.interfaces.tsv"
  local adr="$LFC_RAW_DIR/network.addresses.tsv"
  local rts="$LFC_RAW_DIR/network.routes.tsv"
  local dns="$LFC_RAW_DIR/network.dns.tsv"
  local con="$LFC_RAW_DIR/network.connections.tsv"
  local fw="$LFC_RAW_DIR/network.firewall.tsv"
  local adp="$LFC_RAW_DIR/network.adapters.tsv"

  lfc_tsv_header "$ifc" iface state flags mtu operstate
  lfc_tsv_header "$adr" iface family scope address
  lfc_tsv_header "$rts" destination gateway device protocol
  lfc_tsv_header "$dns" source server
  lfc_tsv_header "$con" protocol state local_address peer_address process
  lfc_tsv_header "$fw" backend status detail
  lfc_tsv_header "$adp" iface driver version firmware

  local out line

  # --- interfaces / addresses / routes (iproute2) --------------------------
  if lfc_have ip; then
    if out=$(ip -o link show 2>/dev/null); then
      while IFS= read -r line; do
        [ -n "$line" ] || continue
        local rest name after flags="" tok mtu="" oper="" st
        rest=${line#*: }
        rest=${rest#"${rest%%[![:space:]]*}"}
        name=${rest%%:*}
        after=${rest#*: }
        # Tokenise: "<FLAGS> mtu N ... state ST ..."
        set -- $after
        while [ $# -gt 0 ]; do
          case "$1" in
            \<*)
              tok="$1"; tok=${tok#<}; tok=${tok%>}
              [ -z "$flags" ] && flags="$tok" ;;
            mtu) shift; mtu="${1:-}" ;;
            state) shift; oper="${1:-}" ;;
          esac
          shift
        done
        [ -n "$oper" ] || oper="unknown"
        case ",$flags," in
          *,UP,*) st="UP" ;;
          *) st="DOWN" ;;
        esac
        lfc_tsv_row "$ifc" "$name" "$st" "$flags" "$mtu" "$oper"
      done <<<"$out"
    else
      lfc_record_skip "network" "interfaces(ip)" "ip link failed"
    fi

    if out=$(ip -o addr show 2>/dev/null); then
      while IFS= read -r line; do
        [ -n "$line" ] || continue
        local idx aif fam addr rest2 scope="" tok2
        read -r idx aif fam addr rest2 <<<"$line"
        aif=${aif%:}
        set -- $rest2
        while [ $# -gt 0 ]; do
          case "$1" in
            scope) shift; scope="${1:-}" ;;
          esac
          shift
        done
        [ -n "$scope" ] || scope="unknown"
        lfc_tsv_row "$adr" "$aif" "$fam" "$scope" "$addr"
      done <<<"$out"
    else
      lfc_record_skip "network" "addresses(ip)" "ip addr failed"
    fi

    if out=$(ip -o route show 2>/dev/null); then
      while IFS= read -r line; do
        [ -n "$line" ] || continue
        local dest gw="" dev="" proto=""
        set -- $line
        dest="${1:-}"
        shift
        while [ $# -gt 0 ]; do
          case "$1" in
            via) shift; gw="${1:-}" ;;
            dev) shift; dev="${1:-}" ;;
            proto) shift; proto="${1:-}" ;;
          esac
          shift
        done
        lfc_tsv_row "$rts" "$dest" "${gw:--}" "${dev:-}" "${proto:-}"
      done <<<"$out"
    else
      lfc_record_skip "network" "routes(ip)" "ip route failed"
    fi

  elif lfc_have ifconfig; then
    if out=$(ifconfig -a 2>/dev/null); then
      while IFS= read -r line; do
        case "$line" in
          *:*)
            # New interface header lines start at column 0 with "name: flags"
            case "$line" in
              " "*|*mtu*|*HWaddr*|*ether*) continue ;;
            esac
            local n
            n=${line%%:*}
            case "$n" in
              *[!A-Za-z0-9._-]*) continue ;;
            esac
            [ -n "$n" ] && lfc_tsv_row "$ifc" "$n" "unknown" "fallback" "" "unknown"
            ;;
        esac
      done <<<"$out"
    fi
    lfc_record_skip "network" "addresses" "ifconfig fallback used (ip not available); limited detail"
  else
    lfc_record_skip "network" "interfaces" "neither ip nor ifconfig available"
  fi

  # --- DNS configuration ---------------------------------------------------
  local dns_used=0
  if lfc_have resolvectl; then
    local rout
    if rout=$(resolvectl dns 2>/dev/null) && [ -n "$rout" ]; then
      dns_used=1
      while IFS= read -r line; do
        [ -n "$line" ] || continue
        local rdev servers s
        rdev=${line%%:*}
        servers=${line#*: }
        for s in $servers; do
          lfc_tsv_row "$dns" "resolvectl:$rdev" "$s"
        done
      done <<<"$rout"
    fi
  fi
  if [ "$dns_used" = "0" ]; then
    if [ -r /etc/resolv.conf ]; then
      while IFS= read -r line; do
        case "$line" in
          nameserver*)
            local srv
            read -r _ srv <<<"$line"
            [ -n "$srv" ] && lfc_tsv_row "$dns" "/etc/resolv.conf" "$srv"
            ;;
        esac
      done </etc/resolv.conf
    else
      lfc_record_skip "network" "dns" "resolvectl unavailable and /etc/resolv.conf unreadable"
    fi
  fi

  # --- active connections (metadata only) ----------------------------------
  local conn_limit=500
  local conn_count=0
  if lfc_have ss; then
    local ss_args=(-Htan)
    [ "${LFC_ELEVATED:-0}" = "1" ] && ss_args=(-Htanp)
    local sout
    if sout=$(ss "${ss_args[@]}" 2>/dev/null); then
      while IFS= read -r line; do
        [ -n "$line" ] || continue
        conn_count=$((conn_count + 1))
        [ "$conn_count" -gt "$conn_limit" ] && break
        local st laddr paddr proc=""
        read -r st _ _ laddr paddr proc <<<"$line"
        lfc_tsv_row "$con" "tcp" "$st" "$laddr" "$paddr" "$proc"
      done <<<"$sout"
      if [ "$conn_count" -gt "$conn_limit" ]; then
        lfc_record_skip "network" "connections" "row limit ${conn_limit} reached"
      fi
      [ "${LFC_ELEVATED:-0}" = "1" ] || \
        lfc_record_skip "network" "connections(process)" "process names require root (rerun with --privileged)"
    else
      lfc_record_skip "network" "connections(ss)" "ss failed"
    fi
  elif lfc_have netstat; then
    local sout2
    if sout2=$(netstat -tan 2>/dev/null); then
      while IFS= read -r line; do
        [ -n "$line" ] || continue
        conn_count=$((conn_count + 1))
        [ "$conn_count" -gt "$conn_limit" ] && break
        local n1 n2 n3 n4 n5 n6
        read -r n1 n2 n3 n4 n5 n6 <<<"$line"
        case "$n1" in
          [Pp]roto|[Tt]cp*|[Uu]dp*) ;;
          *) continue ;;
        esac
        [ "$n1" = "Proto" ] && continue
        local proto laddr paddr st
        if [[ "$n2" =~ ^[0-9]+$ && "$n3" =~ ^[0-9]+$ ]]; then
          # Unix netstat: proto recvq sendq local foreign state
          proto="$n1"; laddr="$n4"; paddr="$n5"; st="$n6"
        else
          # Windows netstat: proto local foreign state
          proto="$n1"; laddr="$n2"; paddr="$n3"; st="$n4"
        fi
        lfc_tsv_row "$con" "$proto" "$st" "$laddr" "$paddr" ""
      done <<<"$sout2"
    else
      lfc_record_skip "network" "connections(netstat)" "netstat failed"
    fi
  else
    lfc_record_skip "network" "connections" "neither ss nor netstat available"
  fi

  # --- firewall status -----------------------------------------------------
  local fw_backend="" fw_status="" fw_detail=""
  if lfc_have ufw && ufw status 2>/dev/null | head -n 1 | grep -q "Status:"; then
    fw_backend="ufw"
    fw_status=$(ufw status 2>/dev/null | { read -r _ s; printf '%s' "$s"; })
    fw_detail=$(ufw status verbose 2>/dev/null | head -n 5 | tr '\n' '; ')
  elif lfc_have firewall-cmd; then
    fw_backend="firewalld"
    if firewall-cmd --state >/dev/null 2>&1; then
      fw_status="active"
      fw_detail=$(firewall-cmd --state 2>/dev/null || echo "")
    else
      fw_status="inactive"
      fw_detail=""
    fi
  elif lfc_have nft; then
    fw_backend="nftables"
    if nft list ruleset >/dev/null 2>&1; then
      fw_status="ruleset-readable"
      local chains
      chains=$(nft list ruleset 2>/dev/null | grep -cE '^[[:space:]]*(chain|rule)' || echo 0)
      fw_detail="chains/rules: ${chains}"
    else
      fw_status="unknown"
      fw_detail="nft present but ruleset not readable (root required)"
    fi
  elif lfc_have iptables; then
    fw_backend="iptables"
    local rules
    if rules=$(iptables -S 2>/dev/null); then
      fw_status="active"
      fw_detail="rules: $(printf '%s\n' "$rules" | grep -c '^-A' || echo 0)"
    else
      fw_status="unknown"
      fw_detail="iptables present but not readable without root"
    fi
  else
    fw_backend="none"
    fw_status="not-detected"
    fw_detail="no known firewall tool found (ufw/firewalld/nft/iptables)"
  fi
  lfc_tsv_row "$fw" "$fw_backend" "$fw_status" "$fw_detail"
  lfc_audit "OK" "firewall backend=$fw_backend status=$fw_status"

  # --- adapter drivers -----------------------------------------------------
  if lfc_have ethtool && lfc_have ip; then
    local iface_list ifs
    iface_list=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | awk '{print $1}' || true)
    for ifs in $iface_list; do
      local edata drv="" ver="" fwb="" eline
      edata=$(ethtool -i "$ifs" 2>/dev/null || true)
      while IFS= read -r eline; do
        case "$eline" in
          driver:*) drv="${eline#driver:}" ;;
          version:*) ver="${eline#version:}" ;;
          firmware-version:*) fwb="${eline#firmware-version:}" ;;
        esac
      done <<<"$edata"
      drv=${drv#"${drv%%[![:space:]]*}"}
      ver=${ver#"${ver%%[![:space:]]*}"}
      fwb=${fwb#"${fwb%%[![:space:]]*}"}
      lfc_tsv_row "$adp" "$ifs" "${drv:-unknown}" "${ver:--}" "${fwb:--}"
    done
  else
    lfc_record_skip "network" "adapter-drivers" "ethtool not available"
  fi

  # Explicit statement of exclusions for the report.
  local excl="$LFC_RAW_DIR/network.exclusions.tsv"
  lfc_tsv_header "$excl" item status
  lfc_tsv_row "$excl" "packet capture / sniffing" "NOT PERFORMED"
  lfc_tsv_row "$excl" "credential capture" "NOT PERFORMED"
  lfc_tsv_row "$excl" "traffic interception" "NOT PERFORMED"
  lfc_tsv_row "$excl" "payload inspection" "NOT PERFORMED"

  lfc_audit "OK" "network audit complete"
}
