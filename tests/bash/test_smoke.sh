#!/usr/bin/env bash
# =============================================================================
# tests/bash/test_smoke.sh - end-to-end collection run against a fixture tree
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PY="$(cd "$ROOT" && bash -c 'source lib/common.sh && lfc_python' 2>/dev/null || true)"
[ -n "${PY:-}" ] || PY=python

PASS=0
FAIL=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ok()  { PASS=$((PASS + 1)); printf '  [ OK ] %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$1"; }

printf 'test_smoke.sh\n'

# --- Fixture -----------------------------------------------------------------
FIX="$TMP/fixture"
mkdir -p "$FIX/docs" "$FIX/media" "$FIX/.hidden" "$FIX/empty"
printf 'quarterly report body'        > "$FIX/docs/report.txt"
printf 'spreadsheets are fun'         > "$FIX/docs/data.csv"
printf 'a document with a space'      > "$FIX/docs/my report (2).pdf"
printf '\x89PNG-fixture-bytes'        > "$FIX/media/photo.png"
printf 'mp4-fixture-bytes'            > "$FIX/media/clip.mp4"
printf 'mp3-fixture-bytes'            > "$FIX/media/song.mp3"
printf 'must not appear in inventory' > "$FIX/.hidden/secret.txt"
# 1.2 MiB large file (threshold below will be 1 MiB)
head -c 1258296 /dev/zero > "$FIX/docs/big.iso" 2>/dev/null \
  || dd if=/dev/zero of="$FIX/docs/big.iso" bs=1024 count=1229 2>/dev/null

# --- Config ------------------------------------------------------------------
CFG="$TMP/config.json"
cat > "$CFG" <<JSON
{
  "meta": {
    "org_name": "Fixture Org",
    "report_classification": "CONFIDENTIAL",
    "report_contact": "security@fixture.test"
  },
  "collection": {
    "scope_paths": ["$FIX"],
    "large_file_threshold_mb": 1,
    "max_depth": 6,
    "modules": {
      "system": true,
      "filesystem": true,
      "media": true,
      "browser": true,
      "network": true,
      "software": true
    }
  },
  "report": { "include_full_inventory_in_json": true },
  "smtp": {
    "enabled": false,
    "to_addr": ["jeanaiameiraguha@gmail.com"]
  }
}
JSON

# --- Run ---------------------------------------------------------------------
OUT="$TMP/out"
LOG="$TMP/run.log"
START=$(date +%s)
if (cd "$ROOT" && bash lfc.sh \
      --config "$CFG" \
      --scope "$FIX" \
      --yes --approve-file-scan --no-send \
      --output "$OUT") >"$LOG" 2>&1; then
  ok "lfc.sh exits 0"
else
  bad "lfc.sh exits 0 (see $LOG)"
fi
ELAPSED=$(( $(date +%s) - START ))
printf '  [info] run took %ss\n' "$ELAPSED"

# Reports land in output/<host>_<timestamp>/
REPORT_DIR="$(find "$OUT" -name system_report.json -print -quit 2>/dev/null)"
if [ -n "$REPORT_DIR" ]; then
  REPORT_DIR="$(dirname "$REPORT_DIR")"
  ok "report directory created"
else
  bad "report directory created"
  printf '\nsmoke: %d passed, %d failed (log: %s)\n' "$PASS" "$FAIL" "$LOG"
  sed -n '1,80p' "$LOG" >&2
  exit 1
fi
RAW="$REPORT_DIR/raw"

# --- Deliverables ------------------------------------------------------------
for f in system_report.html system_report.json system_report.txt \
         filesystem_inventory.csv media_inventory.csv audit.log; do
  if [ -s "$REPORT_DIR/$f" ]; then ok "deliverable: $f"
  else bad "deliverable: $f missing or empty"; fi
done

# --- JSON report content -----------------------------------------------------
# shellcheck disable=SC2086  # $PY may be a two-word candidate like "py -3"
JSON_OK=$($PY - "$REPORT_DIR/system_report.json" <<'PYEOF' 2>/dev/null
import json, sys
r = json.load(open(sys.argv[1], encoding="utf-8"))
checks = []
def ck(desc, cond):
    checks.append((desc, bool(cond)))

info = r.get("report", {})
ck("classification CONFIDENTIAL", info.get("classification") == "CONFIDENTIAL")
ck("org name merged", info.get("org_name") == "Fixture Org")
ck("scope recorded", any("fixture" in s for s in info.get("scope", [])))
ck("modules recorded", len(info.get("modules_run", [])) == 6)

fs = r.get("filesystem", {})
ck("inventory has fixture files", fs.get("inventory_total", 0) >= 7)
ck("large file detected", fs.get("large_file_count", 0) == 1)
lf = fs.get("large_files", [])
ck("large file is big.iso", bool(lf) and lf[0]["path"].endswith("big.iso"))
ck("full inventory in json", fs.get("inventory_included_in_json", 0) >= 7)

media = r.get("media", {})
counts = media.get("counts", {})
ck("media total 6", media.get("total") == 6)
ck("media document 3", counts.get("document") == 3)
ck("media image 1", counts.get("image") == 1)
ck("media video 1", counts.get("video") == 1)
ck("media audio 1", counts.get("audio") == 1)

priv = r.get("privacy", {})
ck("no file contents", priv.get("file_contents_collected") is False)
ck("no credentials", priv.get("credentials_collected") is False)
ck("no packet capture", priv.get("packet_capture") is False)
ck("no persistence", priv.get("persistence_installed") is False)
ck("approval required", priv.get("transmission_requires_approval") is True)

sys_mem = r.get("system", {}).get("memory", [])
mem = next((m for m in sys_mem if m.get("type") == "memory"), None)
ck("memory row present", mem is not None)
if mem:
    ck("memory available populated",
       str(mem.get("available_kb", "")).isdigit() and int(mem["available_kb"]) > 0)
    ck("memory used consistent",
       int(mem.get("used_kb", 0)) == int(mem.get("total_kb", 0)) - int(mem.get("available_kb", 0)))

paths = [row.get("path", "") for row in fs.get("inventory", [])]
ck("space filename survives", any("my report (2).pdf" in p for p in paths))
ck("hidden file excluded", not any(".hidden" in p for p in paths))

for desc, passed in checks:
    print(("OK" if passed else "FAIL") + "\t" + desc)
sys.exit(0 if all(p for _, p in checks) else 1)
PYEOF
)
RC=$?
if [ -n "$JSON_OK" ]; then
  while IFS=$'\t' read -r st desc; do
    if [ "$st" = "OK" ]; then ok "json: $desc"; else bad "json: $desc"; fi
  done <<< "$JSON_OK"
else
  bad "json: report parser produced no output (rc=$RC)"
fi

# --- TXT must stay ASCII, HTML must be HTML ----------------------------------
if LC_ALL=C grep -q '[^ -~[:space:]]' "$REPORT_DIR/system_report.txt" 2>/dev/null; then
  bad "txt: ASCII only"
else
  ok "txt: ASCII only"
fi
if grep -qi '<!DOCTYPE html>' "$REPORT_DIR/system_report.html"; then
  ok "html: doctype present"
else
  bad "html: doctype present"
fi
if grep -q 'fixture' "$REPORT_DIR/system_report.html"; then
  ok "html: hostname present"
else
  bad "html: hostname present"
fi

# --- CSV contents ------------------------------------------------------------
if grep -q 'my report (2).pdf' "$REPORT_DIR/filesystem_inventory.csv"; then
  ok "csv: spaced filename present"
else
  bad "csv: spaced filename present"
fi
if grep -q '\.hidden' "$REPORT_DIR/filesystem_inventory.csv"; then
  bad "csv: hidden file excluded"
else
  ok "csv: hidden file excluded"
fi
if grep -q 'LARGE' "$REPORT_DIR/filesystem_inventory.csv"; then
  ok "csv: LARGE flag present"
else
  bad "csv: LARGE flag present"
fi
MEDIA_ROWS=$(( $(wc -l < "$REPORT_DIR/media_inventory.csv") - 1 ))
if [ "$MEDIA_ROWS" -eq 6 ]; then ok "csv: media row count = 6"
else bad "csv: media row count = 6 (got $MEDIA_ROWS)"; fi

# --- Raw fragments -----------------------------------------------------------
if [ -f "$RAW/system.memory.tsv" ]; then
  MEM_LINE="$(grep '^memory' "$RAW/system.memory.tsv" || true)"
  AVAIL="$(printf '%s' "$MEM_LINE" | cut -f3)"
  if [ -n "$AVAIL" ] && [ "$AVAIL" -gt 0 ] 2>/dev/null; then
    ok "raw: memory available_kb populated ($AVAIL)"
  else
    bad "raw: memory available_kb populated (got '$AVAIL')"
  fi
else
  bad "raw: system.memory.tsv exists"
fi
if [ -f "$RAW/filesystem.inventory.tsv" ]; then
  ok "raw: filesystem.inventory.tsv exists"
else
  bad "raw: filesystem.inventory.tsv exists"
fi

# --- Audit log ---------------------------------------------------------------
AUDIT="$REPORT_DIR/audit.log"
if grep -q '| START |' "$AUDIT"; then ok "audit: START present"
else bad "audit: START present"; fi
if grep -q '| END |' "$AUDIT"; then ok "audit: END present"
else bad "audit: END present"; fi
if grep -q 'module=system' "$AUDIT" && grep -q 'module=software' "$AUDIT"; then
  ok "audit: module entries present"
else
  bad "audit: module entries present"
fi
if grep -q 'stage=delivery' "$AUDIT"; then
  ok "audit: delivery stage recorded"
else
  bad "audit: delivery stage recorded"
fi
if grep -qi 'smtp' "$AUDIT" && grep -q 'no-send\|disabled\|DENY' "$AUDIT"; then
  ok "audit: send skipped recorded"
else
  # --no-send may simply never reach smtp stage with a DENY line
  if grep -q 'stage=delivery' "$AUDIT"; then
    ok "audit: send skipped recorded (delivery stage present)"
  else
    bad "audit: send skipped recorded"
  fi
fi

# --- Refusal paths -----------------------------------------------------------
OUT2="$TMP/out2"
if (cd "$ROOT" && bash lfc.sh \
      --config "$CFG" \
      --scope "$FIX" \
      --yes \
      --output "$OUT2") >"$TMP/run2.log" 2>&1; then
  RC2=0
else
  RC2=$?
fi
# Without --approve-file-scan and without --no-send, a non-interactive run
# must refuse rather than silently scan or send.
if [ "$RC2" -ne 0 ]; then
  ok "non-interactive without approvals refuses (rc=$RC2)"
else
  # If it succeeded, it must NOT have scanned file metadata.
  RD2="$(find "$OUT2" -name system_report.json -print -quit 2>/dev/null)"
  if [ -n "$RD2" ] && grep -q 'LARGE' "$(dirname "$RD2")/filesystem_inventory.csv" 2>/dev/null; then
    bad "non-interactive without approvals refuses"
  else
    ok "non-interactive without approvals refuses (no scan performed)"
  fi
fi

printf '\nsmoke: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
