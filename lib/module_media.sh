#!/usr/bin/env bash
# =============================================================================
# lib/module_media.sh — Module C: Media inventory
# =============================================================================
# Produces:
#   raw/media.inventory.tsv    category / path / size_bytes / mtime_epoch /
#                              extension / flags
#   raw/media.summary.tsv      metric / value
#
# When the filesystem module already ran, media rows were produced by the
# same find pass (single scan, no duplicate I/O). If the filesystem module
# was skipped, this module performs its own metadata-only scan.
# PRIVACY: metadata only — no file contents are read.
# =============================================================================

# Append per-category counts from a media inventory fragment to its summary.
lfc_media_summary_counts() {
  local media="$1" sum="$2" cat
  for cat in document image video audio; do
    lfc_tsv_kv "$sum" "count_${cat}" \
      "$(awk -F'\t' -v c="$cat" '$1==c' "$media" 2>/dev/null | wc -l | tr -d ' ')"
  done
}

lfc_module_media() {
  LFC_MODULE=media
  LFC_STAGE=collect
  lfc_audit "START" "media inventory (metadata only)"

  local media="$LFC_RAW_DIR/media.inventory.tsv"
  local sum="$LFC_RAW_DIR/media.summary.tsv"
  lfc_tsv_header "$sum" metric value

  if [ -f "$media" ]; then
    # Derived from the filesystem module's single find pass.
    local rows
    rows=$(($(wc -l <"$media" 2>/dev/null || echo 1) - 1))
    [ "$rows" -lt 0 ] && rows=0
    lfc_tsv_kv "$sum" "source" "filesystem-module-shared-scan"
    lfc_tsv_kv "$sum" "media_files" "$rows"
    lfc_tsv_kv "$sum" "contents_collected" "no"
    lfc_media_summary_counts "$media" "$sum"
    lfc_audit "OK" "media inventory derived from filesystem pass (${rows} entries)"
    return 0
  fi

  # --- standalone scan (filesystem module skipped) -------------------------
  lfc_tsv_header "$media" category path size_bytes mtime_epoch extension flags
  lfc_tsv_kv "$sum" "source" "standalone-scan"

  local start_ts end_ts
  start_ts=$(date +%s 2>/dev/null || echo 0)

  local root
  local files=0
  if [ ${#LFC_SCOPE_PATHS[@]} -eq 0 ]; then
    lfc_record_skip "media" "scan" "no scope paths configured"
  fi
  for root in "${LFC_SCOPE_PATHS[@]}"; do
    lfc_log "Scanning media (metadata only): $root"
    # want_media=1, want_inventory=0
    lfc_scan_tree "$root" 1 0
  done

  end_ts=$(date +%s 2>/dev/null || echo 0)

  files=$(($(wc -l <"$media" 2>/dev/null || echo 1) - 1))
  [ "$files" -lt 0 ] && files=0

  lfc_tsv_kv "$sum" "media_files" "$files"
  lfc_tsv_kv "$sum" "elapsed_seconds" "$(( end_ts - start_ts ))"
  lfc_tsv_kv "$sum" "contents_collected" "no"
  lfc_media_summary_counts "$media" "$sum"

  lfc_audit "OK" "media inventory standalone scan: ${files} entries"
}
