# Linux Forensic Collector (LFC)

**Open, reviewable diagnostic & digital-forensics collection for Linux.**

LFC is a modular collection utility you run **on your own machine**, with your
explicit authorization, to gather system, filesystem, media, browser, network
and software *metadata* into structured reports you can review before anything
leaves the host.

> **Nothing runs until you run it.** Opening the project page, downloading the
> archive or reading this README executes nothing. Collection starts only when
> you execute `./lfc.sh` from a terminal, and reports are transmitted only
> after you explicitly approve sending.

---

## Contents

- [What LFC does](#what-lfc-does)
- [What LFC never does](#what-lfc-never-does)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Generated reports](#generated-reports)
- [Configuration](#configuration)
- [Email delivery (SMTP)](#email-delivery-smtp)
- [Verifying downloads (SHA-256)](#verifying-downloads-sha-256)
- [Testing](#testing)
- [Project layout](#project-layout)
- [Security & privacy](#security--privacy)
- [License](#license)

---

## What LFC does

| Module | Collected (metadata only) |
|---|---|
| **system** | Distribution, kernel, CPU, memory, swap, storage, mounted filesystems, uptime, hardware model |
| **filesystem** | Path, size, mtime, extension, category and LARGE flag for every file in scope; directory counts; large-file list |
| **media** | Categorized inventory of documents, images, video and audio (same single scan pass as filesystem) |
| **browser** | Browser installs/versions, profile locations, allowlisted security preferences (safe-browsing, Do-Not-Track, TLS settings) |
| **network** | Interfaces, addresses, routes, DNS servers, connection metadata (no payloads), firewall status, adapter drivers |
| **software** | Installed packages, versions, running/enabled services, available package managers |

Every run also produces `audit.log` — a complete, append-only record of what
was collected, what was skipped and why, and whether transmission was
approved, denied or disabled.

## What LFC never does

- **No file contents** — paths, sizes and timestamps only; never reads, copies
  or uploads file bodies.
- **No credentials** — never touches password stores, cookies, session tokens,
  private keys or autofill data.
- **No packet capture** — connection metadata only; no sniffing, no
  interception, no payload inspection.
- **No silent escalation** — `--privileged` asks first; sudo is never invoked
  without approval.
- **No persistence** — installs no services, cron jobs, autostart entries or
  background agents.
- **No transmission without approval** — SMTP delivery requires an explicit
  interactive confirmation or the `--approve-send` flag; otherwise reports stay
  local.

See [SECURITY.md](SECURITY.md) for the full policy.

## Requirements

- Linux with Bash 4.4+ (tested on Ubuntu, Debian, Mint, Fedora, Arch)
- Python 3.8+ (standard library only — no third-party packages)
- Common coreutils (`find`, `awk`, `grep`, `sort`, `sha256sum`)

Missing optional commands (`ss`, `ip`, `free`, `lsblk`, …) are detected at
runtime and recorded as *skipped operations* instead of failing the run.

## Installation

```bash
# 1. Extract the release archive
tar -xzf lfc-1.0.0.tar.gz
cd linux-forensic-collector

# 2. Run the installer (checks prerequisites, prepares config, sets +x)
./install.sh

# 3. Review and edit the configuration
edit config/lfc.config.json      # recipient address, scan scope, limits

# 4. Preview what would happen (executes nothing)
./lfc.sh --dry-run
```

## Usage

```bash
./lfc.sh                          # interactive run (asks before scanning/sending)
./lfc.sh --help                   # all options
./lfc.sh --dry-run                # print the collection plan and exit
./lfc.sh --scope /path/to/dir     # override the scan scope from config
./lfc.sh --no-send                # generate reports, never transmit
./lfc.sh --yes                    # non-interactive (still needs approval flags)
./lfc.sh --approve-file-scan      # pre-authorize file metadata scanning
./lfc.sh --approve-send           # pre-authorize SMTP transmission
./lfc.sh --verbose                # show audit events live
./lfc.sh --skip network           # skip one module
./lfc.sh --only system            # run only one module
```

**Non-interactive rules (privacy first):**

- Without `--approve-file-scan`, file scanning is refused and the
  filesystem/media modules are skipped.
- Without `--approve-send`, reports are generated but never transmitted.

**Exit codes:** `0` success · `1` fatal error · `2` approval required ·
`3` configuration error · `4` attachment too large · `5` SMTP failure.

## Generated reports

Each run creates `output/<hostname>_<UTC-timestamp>/` containing:

| File | Purpose |
|---|---|
| `system_report.html` | Browsable human-readable report |
| `system_report.json` | Machine-readable structured report |
| `system_report.txt` | Plain-text summary (ASCII) for terminals/tickets |
| `filesystem_inventory.csv` | Full filesystem metadata inventory |
| `media_inventory.csv` | Categorized media inventory |
| `audit.log` | Complete action trail for the run |
| `raw/*.tsv` | Raw collection fragments (source of truth) |

Reports are written `0600` (owner-only) and classified **CONFIDENTIAL** by
default (configurable via `meta.report_classification`).

## Configuration

`config/config.template.json` ships with safe defaults:

```jsonc
{
  "meta":    { "org_name": "...", "report_classification": "CONFIDENTIAL" },
  "collection": {
    "scope_paths": ["$HOME"],          // expanded at load time
    "large_file_threshold_mb": 500,     // files at/above get LARGE flag
    "max_depth": 10, "max_files": 100000,
    "include_hidden_paths": false,
    "modules": { "system": true, "filesystem": true, "media": true,
                 "browser": true, "network": true, "software": true }
  },
  "smtp": {
    "enabled": false,                   // stays false until you opt in
    "host": "", "port": 587, "tls_mode": "starttls",
    "username_env": "LFC_SMTP_USERNAME",   // credentials live ONLY in env
    "password_env": "LFC_SMTP_PASSWORD",
    "to_addr": ["jeanaiameiraguha@gmail.com"],
    "max_attachment_mb": 20, "attach_format": "zip"
  }
}
```

`install.sh` copies the template to `config/lfc.config.json` (your local,
editable config). Values are validated on every run; invalid configuration
aborts before any collection starts.

## Email delivery (SMTP)

Delivery is **off by default** (`smtp.enabled=false`). To enable it:

1. Set `smtp.enabled=true`, `smtp.host`, `smtp.from_addr` in your config.
2. Export credentials as environment variables — never in files:

   ```bash
   export LFC_SMTP_USERNAME='your-login'
   export LFC_SMTP_PASSWORD='your-app-password'
   ```

3. Run `./lfc.sh`. At the end you will see a transmission preview and be asked
   to confirm. Pre-authorize with `--approve-send` for scripted runs.

The bundle (zip of all five reports + `audit.log`) is size-checked
(`smtp.max_attachment_mb`) *before* any network connection is opened.
Credential half-configuration (one env var set, the other empty) is refused.

## Verifying downloads (SHA-256)

```bash
# Download SHA256SUMS.txt alongside the archive, then:
sha256sum lfc-1.0.0.tar.gz
cat SHA256SUMS.txt
# The two hashes must match exactly.

# Or use the bundled helper (compares every file, executes nothing):
./tools/verify_checksums.sh /path/to/downloads
```

If a checksum does not match, **do not run the file** — re-download it and
report the discrepancy.

## Testing

```bash
./tests/run_tests.sh           # full suite
./tests/run_tests.sh --quick   # skip the end-to-end smoke test
```

The suite uses only the Python standard library (`unittest`) and Bash:

- `tests/python/` — config validation, fragment escape/round-trip, report
  generation, browser allowlist policy, SMTP approval/size/credential gates
  (SMTP fully mocked).
- `tests/bash/test_common.sh` — TSV writers, module gating, audit format,
  bash→Python escape round-trip.
- `tests/bash/test_smoke.sh` — full `lfc.sh` run on a fixture tree asserting
  all five deliverables, privacy flags, large-file detection, hidden-file
  exclusion, ASCII TXT output and the audit trail.

## Project layout

```
linux-forensic-collector/
├── lfc.sh                     # main orchestrator (approval workflow)
├── install.sh                 # prerequisite check + config bootstrap
├── lib/
│   ├── common.sh              # logging, audit, fork-free TSV writers
│   ├── detect.sh              # distro/tooling detection
│   ├── permissions.sh         # privilege detection & opt-in elevation
│   ├── delivery.sh            # SMTP preview/send helpers (bash side)
│   └── module_*.sh            # collection modules (system, filesystem,
│                              #   media, browser, network, software)
├── collector/                 # Python package (report + delivery)
│   ├── config.py              # defaults, validation, config CLI
│   ├── fragments.py           # TSV reader (escape/unescape, CSV writer)
│   ├── browser_prefs.py       # allowlisted preference inspection
│   ├── report_processor.py    # builds JSON/HTML/TXT/CSV reports
│   ├── report_render.py       # HTML & plain-text renderers
│   └── smtp_sender.py         # approval-gated SMTP delivery
├── config/config.template.json
├── web/                       # static landing page (no auto-execution)
├── tools/                     # build_release.sh, verify_checksums.sh
├── docs/ARCHITECTURE.md
├── tests/                     # run_tests.sh + bash/python suites
├── README.md                  # this file
└── SECURITY.md                # full security & privacy policy
```

## Security & privacy

Read [SECURITY.md](SECURITY.md) for the complete policy. Highlights:

- Metadata-only collection; contents are never read or transmitted.
- Credentials only from environment variables, never logged, never written.
- Explicit approval gates for file scanning and email transmission.
- No persistence, no stealth execution, no silent privilege escalation.
- Every run produces an `audit.log` you can review before sharing reports.
- Reports are owner-only (`0600`) and marked CONFIDENTIAL by default.

## License

Use only on systems you are authorized to audit. Reports contain sensitive
system detail — handle them according to your organization's data
classification policy.
#   L i n u x - F o r e n s i c - C o l l e c t o r  
 