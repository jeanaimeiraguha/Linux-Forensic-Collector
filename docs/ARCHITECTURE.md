# ARCHITECTURE.md — Linux Forensic Collector (LFC)

How the pieces fit together, and why they are shaped this way.

---

## 1. High-level flow

```
 operator shell
      │
      ▼
 ┌─────────────┐   sources   ┌──────────────────────────────┐
 │   lfc.sh    │────────────▶│ lib/*.sh                     │
 │ orchestrator│             │  common  detect  permissions │
 │             │             │  module_system/filesystem/…  │
 └──────┬──────┘             │  delivery                    │
        │                    └──────────────────────────────┘
        │ writes                          reads
        ▼                                 │
 ┌──────────────────┐                     │
 │ output/<host>_<ts>/                    │
 │   raw/*.tsv       │────────────────────┘
 │   audit.log       │
 └──────┬───────────┘
        │ python -m collector report
        ▼
 ┌──────────────────────────────────────────┐
 │ collector/ (Python, stdlib only)         │
 │  fragments ─▶ report_processor           │
 │                  ├─▶ report_render (HTML/TXT)
 │                  ├─▶ JSON + CSV          │
 │                  └─▶ print_summary       │
 │  smtp_sender  (approval-gated delivery)  │
 └──────────────────────────────────────────┘
        │
        ▼  (only with explicit approval)
   SMTP relay ──▶ recipient mailbox
```

Two-language split, deliberately:

- **Bash** does what shells are good at: process detection, command
  availability, privilege checks, `find`/`stat`/`ip`/`ss` collection, and
  interactive approval prompts.
- **Python** does what Python is good at: robust JSON validation, structured
  report assembly, HTML/TXT rendering, CSV writing and SMTP/TLS delivery.

The contract between them is the **raw fragment directory** (`raw/*.tsv`).

## 2. The fragment contract

Every module writes tab-separated fragments with a single header row:

```
raw/
  detect.tsv             key / value
  system.general.tsv     key / value
  system.cpu.tsv         field / value
  system.memory.tsv      type / total_kb / available_kb / used_kb / total_human
  system.storage.tsv     device / size / model / transport / rotational / type
  filesystem.inventory.tsv  category / path / size_bytes / mtime_epoch / extension / flags
  media.inventory.tsv    (same columns, media categories only)
  browser.profiles.tsv   browser / profile_name / profile_path / prefs_file
  network.*.tsv          per-facet tables
  software.*.tsv         managers / packages / services / summary
  skipped.tsv            module / operation / reason
  errors.tsv             module / operation / message
```

Rules:

1. **One line per record.** Tab, newline, CR and backslash inside values are
   escaped (`\t`, `\n`, `\r`, `\\`) by fork-free Bash helpers
   (`lfc_tsv_row` in `lib/common.sh`) and unescaped by
   `collector.fragments.unescape`. Paths with spaces, quotes, tabs or
   newlines survive the round trip (tested in
   `tests/bash/test_common.sh` → `tests/python/test_fragments.py`).
2. **Fork-free writers.** Row writing uses pure Bash string operations — no
   `$(…)`, `awk` or `grep` per row. A subshell per row dominated runtime on
   large scans (a 110 s network module became ~2 s after this change).
3. **Passive Python side.** The reporter *only* reads fragments; it never
   gathers new system data. Re-running the reporter on saved `raw/` reproduces
   identical reports (modulo timestamps).

## 3. Orchestration (`lfc.sh`)

Ordered stages, each recorded in `audit.log` with `stage=` and `module=`:

| Stage | What happens | Failure behaviour |
|---|---|---|
| `init` | Parse flags, resolve config, validate JSON, flatten into `LFC_CFG` | abort (exit 3) on invalid config |
| `setup` | Create `output/<host>_<UTC>/`, `audit.log` (0600), TSV headers | abort if mkdir fails |
| `detect` | Distro, tool matrix, Python resolution (`detect.sh`) | records skips |
| `permissions` | Privilege detection; opt-in elevation prompt | continues unprivileged |
| `approval` | File-scan approval gate (interactive or `--approve-file-scan`) | decline → skip filesystem/media, audit `DENY` |
| `collect` | Modules in fixed order: system → filesystem → media → browser → network → software | per-module errors recorded, run continues (no `set -e`) |
| `report` | `python -m collector report` builds the five deliverables | abort (exit 1) |
| `review` | Prints the report paths for the operator | — |
| `delivery` | `--no-send` / `smtp.enabled=false` → audited skip; otherwise preview + approval gate + send | exit 2/3/4/5 per outcome |
| `finalize` | Audit `END` with modules, duration, output path | exit 0 |

Key invariants:

- **No `set -e`.** A failing command inside a module must be recorded
  (`skipped`/`errors`), not kill the run. `set -uo pipefail` still guards
  against unset variables and silent pipe failures.
- **Approval flags are orthogonal**: `--yes` only removes *prompts*; it never
  substitutes for `--approve-file-scan` or `--approve-send`.
- **`LFC_CFG` is associative** (`declare -A`); a plain indexed array makes
  `LFC_CFG[key]` arithmetic-subscript and aborts functions under `set -u`.
- **CRLF defense**: Python's piped stdout is reconfigured to `\n`
  (`collector/__main__.py`) *and* bash strips stray `\r` from parsed lines —
  Windows terminals otherwise corrupt flattened config values.

## 4. Collection modules

Each module lives in `lib/module_<name>.sh`, exposes
`lfc_module_<name>()`, and follows the same skeleton:

```bash
lfc_module_x() {
  LFC_MODULE=x            # audit label
  LFC_STAGE=collect
  lfc_audit "START" "..."
  lfc_tsv_header "$RAW/x....tsv" col col col
  # collect; every missing tool → lfc_record_skip, never a crash
  lfc_audit "OK" "..."
}
```

Notable design points:

- **Single filesystem pass.** `lfc_scan_tree` (in `module_filesystem.sh`)
  takes `want_inventory` / `want_media` parameters so filesystem and media
  share one `find` invocation; the media module reuses the existing
  `media.inventory.tsv` when present instead of re-scanning.
- **Classification** (`lfc_classify_into`) maps extensions to
  `document|image|video|audio|other` (+ `directory` rows); only the four media
  categories are written to the media fragment.
- **Large files** are flagged in-pass (`LARGE`) against
  `collection.large_file_threshold_mb`; the reporter builds the capped
  large-file list from the flag, not from a second scan.
- **Graceful degradation** is the default posture: `ss` missing → recorded
  skip with fallback note; `/proc` absent → recorded skip. The report shows
  exactly what could and could not be collected.

## 5. Python package (`collector/`)

| Module | Responsibility |
|---|---|
| `config.py` | `DEFAULTS`, deep-merge of user JSON, `$HOME` expansion, full validation (`validate()` returns a list of errors), CLI used by bash (`--validate --get --get-array --flatten --print`) |
| `fragments.py` | TSV unescape/read (`read_table`, `read_kv`, `kv_multi`, `load_raw`), `write_csv`, `epoch_to_iso`, `human_bytes` |
| `browser_prefs.py` | Allowlist + denylist policy for preference inspection (see SECURITY.md §5) |
| `report_processor.py` | `build_report()` assembles the report dict; `write_reports()` emits JSON/HTML/TXT/CSV; `print_summary()`; `report_cli` |
| `report_render.py` | `render_html()` (inline CSS, self-contained file) and `render_text()` (**ASCII-only** for terminals/tickets) |
| `smtp_sender.py` | Approval gate → config gate → bundle/size gate → credential env gate → TLS SMTP; exit codes 0/2/3/4/5; audit appends |

Report dict shape (stable contract, also asserted by tests):

```jsonc
{
  "report":     { tool, tool_version, generated_at, hostname, classification,
                  scope, modules_run, duration_seconds, ... },
  "system":     { general, detect, cpu, memory[], storage[], filesystems[] },
  "filesystem": { summary, inventory_total, large_file_count, large_files[],
                  top_categories, inventory[] },
  "media":      { summary, total, total_bytes, counts{category:n}, inventory[] },
  "browser":    { installs[], profiles[], security_preferences, not_accessed[] },
  "network":    { interfaces[], addresses[], routes[], dns[], connections[],
                  firewall[], adapters[], exclusions[] },
  "software":   { managers[], package_count, packages[], services[], summary },
  "collection": { started_at, errors[], skipped[], tools[] },
  "privacy":    { file_contents_collected:false, credentials_collected:false,
                  packet_capture:false, persistence_installed:false,
                  transmission_requires_approval:true, notes[] }
}
```

`privacy` is hardcoded in code — it is a statement of fact about the tool,
not a configurable flag.

## 6. Delivery path

```
lfc.sh (stage=delivery)
  ├─ --no-send                → audit OK "delivery skipped by operator"
  ├─ smtp.enabled=false       → audit OK "delivery skipped: smtp.enabled=false"
  └─ else: preview → approval gate
        └─ approved → python -m collector send --approved
              1. load+validate config            → exit 3 on error
              2. build zip of 5 reports + audit  → exit 3 if incomplete
              3. size vs max_attachment_mb       → exit 4 BEFORE connecting
              4. credentials from env only      → exit 3 on half-config
              5. TLS SMTP send                  → exit 5 on failure
              6. audit DENY/FAIL/OK appended
```

Bash maps exit codes to operator-facing messages (see `lfc.sh` delivery
case-statement). `smtp_sender.py` is fully unit-tested with a mocked
`smtplib`.

## 7. Approval state machine (summary)

```
                 ┌──────────────────────────────┐
                 │ interactive?                 │
                 └──────┬───────────────┬───────┘
                       yes              no (--yes)
                        │                │
              prompt y/N│                │ requires flag
                 ┌──────┴───┐            │
                yes         no           │
                 │          │            │
            scan allowed  audit DENY     │
                                 ┌───────┴────────┐
                                 │ --approve-file-scan?
                                 └───────┬────────┘
                                  no ────┴─── yes
                                   │         │
                            skip fs/media   scan
```

The same shape applies to transmission with `--approve-send`.

## 8. Testing strategy

| Layer | Suite | Proves |
|---|---|---|
| Pure functions | `tests/python/test_fragments.py` | escape round-trip, padding, CSV, epoch/human helpers |
| Config | `tests/python/test_config.py` | template validity, recipient address, no credential keys, CLI contract |
| Privacy policy | `tests/python/test_browser_prefs.py` | allowlist ⊕ denylist invariant, no secret leakage |
| Reports | `tests/python/test_report_processor.py` | five deliverables, JSON contract, ASCII TXT, CSV paths with spaces |
| Delivery | `tests/python/test_smtp_sender.py` | approval/size/credential gates, mocked SMTP success/failure, audit lines |
| Bash units | `tests/bash/test_common.sh` | TSV writers, module gating, audit format, bash→Python round-trip |
| End-to-end | `tests/bash/test_smoke.sh` | full run on fixture tree: deliverables, privacy flags, large-file, hidden exclusion, audit stages, refusal paths |

Runner: `./tests/run_tests.sh [--quick]` (stdlib `unittest` only — no pytest
required).

## 9. Performance notes

- **Fork-free TSV rows** (see §2) — the dominant win.
- **Single `find` pass** shared by filesystem + media.
- **Network module** parses `ip`/`ss`/`netstat` output with pure-Bash reads
  and one `awk` per command (not per row).
- **`find -printf` + NUL-delimited reads** (`read -r -d ''`) — no per-file
  `stat` forks, safe for paths with spaces/newlines.
- Typical fixture run: ~8–13 s wall on a developer machine (mostly Python
  startup + report rendering).

## 10. Extension points

- **New module**: add `lib/module_<name>.sh` implementing
  `lfc_module_<name>()`, register it in `MODULE_ORDER` (lfc.sh), add a
  `collection.modules.<name>` key to `config.py` `DEFAULTS` + `MODULE_NAMES`,
  and source the file in `lfc.sh`.
- **New fragment**: header via `lfc_tsv_header`, rows via `lfc_tsv_row`;
  consume with `raw.table("name")` in `report_processor.build_report()`.
- **New report section**: extend the report dict, then both renderers
  (`render_html`, `render_text`) — keep the TXT renderer ASCII-only.
- **New delivery channel**: implement behind the same approval/size gates as
  `smtp_sender.py`; reuse the exit-code contract.
