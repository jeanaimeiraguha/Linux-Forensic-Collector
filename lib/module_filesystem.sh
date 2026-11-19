#!/usr/bin/env bash
# =============================================================================
# lib/module_filesystem.sh — Module B: Filesystem inventory (metadata only)
# =============================================================================
# Produces:
#   raw/filesystem.inventory.tsv   category / path / size_bytes / mtime_epoch /
#                                  extension / flags
#   raw/filesystem.summary.tsv     metric / value
#
# PRIVACY: this module records METADATA ONLY (path, size, timestamp, type).
# File contents are never opened, copied, hashed for exfiltration, uploaded,
# or transmitted. Scanning of owner-visible paths requires explicit approval
# (handled by lfc.sh before this module runs).
# =============================================================================

# Map a lowercase extension to a content category.
# Sets $LFC_CATEGORY (fork-free — called once per inventoried file).
lfc_classify_into() {
  case "$1" in
    pdf|doc|docx|xls|xlsx|ppt|pptx|odt|ods|odp|rtf|txt|md|csv|epub|pages|numbers|tex|org)
      LFC_CATEGORY="document" ;;
    jpg|jpeg|png|gif|webp|bmp|tif|tiff|heic|heif|svg|ico|raw|cr2|nef|arw|dng|psd)
      LFC_CATEGORY="image" ;;
    mp4|mkv|avi|mov|webm|wmv|flv|m4v|mpg|mpeg|3gp|ts|m2ts)
      LFC_CATEGORY="video" ;;
    mp3|wav|flac|aac|ogg|oga|m4a|wma|opus|alac|aiff)
      LFC_CATEGORY="audio" ;;
    zip|tar|gz|tgz|7z|rar|bz2|xz|zst|jar|iso)
      LFC_CATEGORY="archive" ;;
    sh|bash|py|js|ts|jsx|tsx|c|h|cpp|hpp|java|go|rs|rb|php|pl|lua|sql|yml|yaml|json|xml|ini|conf|cfg|toml)
      LFC_CATEGORY="source" ;;
    *)
      LFC_CATEGORY="other" ;;
  esac
}

# Returns 0 when the path is inside the current run's output directory
# (prevents the collector from inventorying its own growing report files).
lfc_is_output_path() {
  case "$1" in
    "${LFC_OUTPUT_DIR}"/*|"${LFC_OUTPUT_DIR}") return 0 ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# lfc_scan_tree <root> [want_media] [want_inventory]
#   One find pass over <root>. Appends to filesystem.inventory.tsv when
#   want_inventory=1 (default) and to media.inventory.tsv when want_media=1.
#   Shared with module_media.sh so a skipped filesystem module does not
#   prevent media collection (and vice versa).
# ---------------------------------------------------------------------------
lfc_scan_tree() {
  local root="$1"
  local inv="$LFC_RAW_DIR/filesystem.inventory.tsv"
  local media="$LFC_RAW_DIR/media.inventory.tsv"
  local want_media="${2:-0}"
  local want_inventory="${3:-1}"

  local maxdepth="${LFC_MAX_DEPTH:-10}"
  local maxfiles="${LFC_MAX_FILES:-100000}"
  local large_bytes=$(( ${LFC_LARGE_FILE_MB:-500} * 1024 * 1024 ))
  local cross="${LFC_CROSS_FS:-0}"
  local hidden="${LFC_INCLUDE_HIDDEN:-0}"

  # Normalise root to an absolute path so inventory paths are unambiguous.
  if [ -d "$root" ]; then
    root=$(cd -- "$root" 2>/dev/null && pwd -P) || {
      lfc_record_skip "filesystem" "scan" "cannot enter directory: $1"
      return 1
    }
  elif [ -f "$root" ]; then
    root=$(cd -- "$(dirname -- "$root")" 2>/dev/null && pwd -P)/$(basename -- "$root") || {
      lfc_record_skip "filesystem" "scan" "cannot resolve file: $1"
      return 1
    }
  else
    lfc_record_skip "filesystem" "scan" "path missing or not accessible: $1"
    return 1
  fi

  local -a find_cmd=( find "$root" -mindepth 1 -maxdepth "$maxdepth" )
  [ "$cross" = "1" ] || find_cmd+=( -xdev )

  # Always-prune pseudo/system trees; prune hidden paths unless approved.
  find_cmd+=( \( -name node_modules -o -name .cache -o -name .Trash \
                 -o -name .git -o -name __pycache__ -o -name proc \
                 -o -name sys -o -name dev -o -name run \) -prune -o )
  if [ "$hidden" != "1" ]; then
    find_cmd+=( -name '.*' -prune -o )
  fi

  find_cmd+=( \( -type d -printf 'd\t%s\t%T@\t%p\0' \
                 -o -type f -printf 'f\t%s\t%T@\t%p\0' \) )

  local kind size epoch path base ext category flags
  local files=0 dirs=0 skipped_trunc=0
  local total_bytes=0 large_count=0
  local -A cat_count=() cat_bytes=()

  while IFS=$'\t' read -r -d '' kind size epoch path; do
    # Never inventory our own output tree.
    if lfc_is_output_path "$path"; then
      continue
    fi

    epoch=${epoch%%.*}
    [ -n "$epoch" ] || epoch=0
    [ -n "$size" ] || size=0

    if [ "$kind" = "d" ]; then
      dirs=$((dirs + 1))
      [ "$want_inventory" = "1" ] && lfc_tsv_row "$inv" "directory" "$path" "$size" "$epoch" "" ""
      continue
    fi

    files=$((files + 1))
    if [ "$files" -gt "$maxfiles" ]; then
      skipped_trunc=1
      break
    fi

    base="${path##*/}"
    ext=""
    case "$base" in
      *.*) ext="${base##*.}"; ext="${ext,,}" ;;
    esac
    lfc_classify_into "$ext"
    category="$LFC_CATEGORY"

    flags=""
    if [ "$size" -ge "$large_bytes" ] 2>/dev/null; then
      flags="LARGE"
      large_count=$((large_count + 1))
    fi

    total_bytes=$((total_bytes + size))
    cat_count["$category"]=$(( ${cat_count["$category"]:-0} + 1 ))
    cat_bytes["$category"]=$(( ${cat_bytes["$category"]:-0} + size ))

    if [ "$want_inventory" = "1" ]; then
      lfc_tsv_row "$inv" "$category" "$path" "$size" "$epoch" "$ext" "$flags"
    fi

    # Media module consumes the same pass when it is enabled.
    if [ "$want_media" = "1" ]; then
      case "$category" in
        document|image|video|audio)
          lfc_tsv_row "$media" "$category" "$path" "$size" "$epoch" "$ext" ;;
      esac
    fi
  done < <("${find_cmd[@]}" 2>/dev/null)

  if [ "$skipped_trunc" = "1" ]; then
    lfc_record_skip "filesystem" "scan" \
      "file limit reached (${maxfiles}) while scanning ${root}; remaining files not listed"
  fi

  # Per-root counters are accumulated into the summary by the caller via
  # globals so multiple roots merge into one summary table.
  LFC_SCAN_FILES=$(( ${LFC_SCAN_FILES:-0} + files ))
  LFC_SCAN_DIRS=$(( ${LFC_SCAN_DIRS:-0} + dirs ))
  LFC_SCAN_BYTES=$(( ${LFC_SCAN_BYTES:-0} + total_bytes ))
  LFC_SCAN_LARGE=$(( ${LFC_SCAN_LARGE:-0} + large_count ))
  LFC_SCAN_ROOTS=$(( ${LFC_SCAN_ROOTS:-0} + 1 ))
  local k
  for k in "${!cat_count[@]}"; do
    LFC_SCAN_CAT_COUNT["$k"]=$(( ${LFC_SCAN_CAT_COUNT["$k"]:-0} + ${cat_count["$k"]} ))
    LFC_SCAN_CAT_BYTES["$k"]=$(( ${LFC_SCAN_CAT_BYTES["$k"]:-0} + ${cat_bytes["$k"]} ))
  done
  [ "$skipped_trunc" = "1" ] && LFC_SCAN_TRUNCATED=1
  return 0
}

# ---------------------------------------------------------------------------
lfc_module_filesystem() {
  LFC_MODULE=filesystem
  LFC_STAGE=collect
  lfc_audit "START" "filesystem inventory (metadata only)"

  local inv="$LFC_RAW_DIR/filesystem.inventory.tsv"
  local sum="$LFC_RAW_DIR/filesystem.summary.tsv"
  local media="$LFC_RAW_DIR/media.inventory.tsv"

  lfc_tsv_header "$inv" category path size_bytes mtime_epoch extension flags
  lfc_tsv_header "$sum" metric value

  local want_media=0
  if lfc_module_enabled media; then
    want_media=1
    lfc_tsv_header "$media" category path size_bytes mtime_epoch extension flags
  fi

  declare -gA LFC_SCAN_CAT_COUNT=() LFC_SCAN_CAT_BYTES=()
  LFC_SCAN_FILES=0 LFC_SCAN_DIRS=0 LFC_SCAN_BYTES=0 LFC_SCAN_LARGE=0
  LFC_SCAN_ROOTS=0 LFC_SCAN_TRUNCATED=0

  local start_ts end_ts
  start_ts=$(date +%s 2>/dev/null || echo 0)

  local root
  if [ ${#LFC_SCOPE_PATHS[@]} -eq 0 ]; then
    lfc_record_skip "filesystem" "scan" "no scope paths configured"
  fi
  for root in "${LFC_SCOPE_PATHS[@]}"; do
    lfc_log "Scanning (metadata only): $root"
    lfc_scan_tree "$root" "$want_media"
  done

  end_ts=$(date +%s 2>/dev/null || echo 0)

  lfc_tsv_kv "$sum" "roots_scanned" "$LFC_SCAN_ROOTS"
  lfc_tsv_kv "$sum" "files_listed" "$LFC_SCAN_FILES"
  lfc_tsv_kv "$sum" "directories_listed" "$LFC_SCAN_DIRS"
  lfc_tsv_kv "$sum" "total_bytes" "$LFC_SCAN_BYTES"
  lfc_tsv_kv "$sum" "large_files" "$LFC_SCAN_LARGE"
  lfc_tsv_kv "$sum" "large_file_threshold_mb" "${LFC_LARGE_FILE_MB:-500}"
  lfc_tsv_kv "$sum" "max_depth" "${LFC_MAX_DEPTH:-10}"
  lfc_tsv_kv "$sum" "max_files" "${LFC_MAX_FILES:-100000}"
  lfc_tsv_kv "$sum" "include_hidden" "$([ "${LFC_INCLUDE_HIDDEN:-0}" = 1 ] && echo yes || echo no)"
  lfc_tsv_kv "$sum" "cross_filesystems" "$([ "${LFC_CROSS_FS:-0}" = 1 ] && echo yes || echo no)"
  lfc_tsv_kv "$sum" "truncated" "$([ "${LFC_SCAN_TRUNCATED:-0}" = 1 ] && echo yes || echo no)"
  lfc_tsv_kv "$sum" "elapsed_seconds" "$(( end_ts - start_ts ))"
  lfc_tsv_kv "$sum" "contents_collected" "no"

  local k
  for k in "${!LFC_SCAN_CAT_COUNT[@]}"; do
    lfc_tsv_kv "$sum" "category_${k}_count" "${LFC_SCAN_CAT_COUNT[$k]}"
    lfc_tsv_kv "$sum" "category_${k}_bytes" "${LFC_SCAN_CAT_BYTES[$k]:-0}"
  done

  lfc_audit "OK" "filesystem inventory: files=${LFC_SCAN_FILES} dirs=${LFC_SCAN_DIRS} large=${LFC_SCAN_LARGE}"
}
