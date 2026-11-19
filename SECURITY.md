# SECURITY.md — Linux Forensic Collector (LFC)

**Classification of reports: CONFIDENTIAL (default).**
This document is the authoritative security and privacy policy for LFC. It
applies to the collection engine, the Python reporter/delivery pack, the
installer, the web landing page and every release artifact.

---

## 1. Design principles

1. **Nothing runs automatically.** LFC executes only when an operator runs
   `./lfc.sh` from a terminal. The web page, downloads and docs never
   auto-execute anything. No cron entries, no systemd units, no shell
   profiles, no desktop autostart are created by LFC — ever.
2. **Metadata only.** Collection records *facts about* files and systems
   (paths, sizes, timestamps, versions, states). File **contents** are never
   read, copied, hashed, compressed into the report, or transmitted.
3. **Explicit approval for every sensitive step.** File metadata scanning and
   email transmission each require a separate, explicit operator approval —
   interactively, or via dedicated CLI flags for scripted runs.
4. **Least data, shortest retention.** Scope, depth and file-count limits are
   configurable; large-file lists are capped; JSON inventory embedding is
   opt-in. Reports are owner-only (`0600`) and the operator controls
   deletion.
5. **No stealth.** Every action is recorded in `audit.log`. Skips, errors,
   denials and elevations are logged, not hidden.

## 2. What LFC collects

| Area | Collected |
|---|---|
| System | Hostname, distro, kernel, arch, CPU model/cores, memory & swap totals, storage devices, mounted filesystems, uptime |
| Filesystem | Per file: path, size, mtime epoch, extension, content category, LARGE flag; per directory: counts; totals per category |
| Media | The document/image/video/audio subset of the filesystem pass (same scan, no extra I/O) |
| Browser | Installed browsers and versions, profile paths, **allowlisted** security preferences only (see §5) |
| Network | Interface names/states/MTU, addresses, routes, DNS server list, TCP/UDP connection metadata (states, endpoints, process names — no payloads), firewall backend/status, adapter drivers |
| Software | Package manager availability, installed package names/versions, service unit states |
| Run metadata | Scope paths, modules run, duration, timestamps, skip/error registers, tool availability matrix |

## 3. What LFC never collects

- **File contents** of any kind (documents, images, media, archives, code).
- **Credentials or secrets**: passwords, password-store files
  (`logins.json`, `Login Data`, `keyrings`, `*.pem`, `id_rsa`, …), cookies,
  session tokens, API keys, autofill data, wallet files, SSH authorized
  keys.
- **Personal content**: email bodies, chat logs, browser history, form
  contents, clipboard data.
- **Traffic**: no packet capture, no sniffing, no proxying, no DNS query
  logging, no payload inspection. Only socket *metadata* already exposed by
  the OS (`ss`/`netstat`).
- **Screenshots, keystrokes, microphones, cameras.**
- **Other users' data** without the same explicit scope approval.

## 4. Approval gates

| Gate | Interactive | Non-interactive (`--yes`) |
|---|---|---|
| File metadata scan | Prompt lists the scope and states that only metadata is recorded; decline skips filesystem+media | Requires `--approve-file-scan`; otherwise filesystem+media are skipped and the denial is audited |
| Privileged metadata (`--privileged`) | Prompts for sudo first; refusal continues unprivileged | Requires `--approve-elevate`; otherwise runs unprivileged |
| SMTP transmission | Preview of host/recipients/attachment size, then explicit y/N | Requires `--approve-send`; otherwise reports stay local and the denial is audited |

There is **no** configuration value that silently enables transmission:
`smtp.enabled=true` only makes the delivery *stage* reachable — the operator
still has to approve the send (or pass `--approve-send`).

## 5. Browser inspection policy

`collector/browser_prefs.py` reads preference files **only** to extract a
small allowlist of non-sensitive security posture indicators
(`safebrowsing.*`, `do_not_track`, OCSP stapling, TLS minimum version, URL-bar
suggestion settings, …).

- An entry is emitted only if its dotted path equals or ends with an
  allowlisted key.
- A denylist regex (`password|cookie|token|secret|credential|private key|
  api key|session|autofill|payment|…`) vetoes any path or string value —
  including values inside allowed keys.
- Values are limited to booleans, numbers and strings ≤ 64 characters.
- The test suite (`tests/python/test_browser_prefs.py`) asserts that **no
  allowlisted key matches the denylist**, so adding a credential-like key
  fails CI and forces review.
- Password stores, cookie stores, session files and history are never opened.

## 6. Credential handling (SMTP)

- Credentials exist **only** in environment variables named by the config
  (`smtp.username_env` / `smtp.password_env`, defaults
  `LFC_SMTP_USERNAME` / `LFC_SMTP_PASSWORD`).
- They are never stored in JSON config, never written to disk, never logged,
  never echoed to the console, never included in reports or the audit log.
- Half-configuration (one of the two variables set) is refused with a config
  error before any connection is opened.
- The audit log records only *that* a send was attempted and its outcome —
  never the credentials.

## 7. Transmission controls

1. **Size first**: the attachment bundle is built and measured against
   `smtp.max_attachment_mb` *before* any network socket is opened. Oversized
   bundles exit with code 4 without connecting.
2. **TLS by default**: `tls_mode=starttls` (or `ssl`) with the system CA
   store; `none` must be explicitly configured (lab relays only).
3. **Approval**: see §4. Refusals exit with code 2 and are audited as `DENY`.
4. **Bundle contents**: exactly the five report files + `audit.log`, zipped.
   Raw `raw/*.tsv` fragments are not attached by default (`--raw` is an
   explicit opt-in used by the preview path).
5. **Failure isolation**: SMTP failures exit with code 5, are audited as
   `FAIL`, and never corrupt or delete local reports.

## 8. Privilege handling

- LFC runs **unprivileged by default** and still produces useful reports
  (missing privileged data appears as `skipped` operations).
- `--privileged` / `--approve-elevate` request sudo *only after* an explicit
  prompt or flag; there is no password capture, no `NOPASSWD` changes, no
  `sudoers` edits, no setuid binaries.
- Elevation applies only to individual metadata commands (e.g. reading
  `/proc`, hardware details), never to arbitrary code execution.

## 9. Filesystem & output safety

- Output directories are created `0700`; report files are `0600`.
- LFC never inventories its own output tree (`lfc_is_output_path` guard).
- Collection never modifies, moves or deletes scanned files — read-only
  metadata operations only (`find -printf`, `stat`, `df`, `ip`, `ss`, …).
- Hidden paths are excluded unless `collection.include_hidden_paths=true`.
- `find` prunes `.*` directories by default so sensitive dot-directories are
  not traversed without an explicit opt-in.

## 10. Web page & release integrity

- The landing page (`web/`) contains **no automatic script execution**:
  `script.js` only reads `SHA256SUMS.txt` for display and wires
  copy-to-clipboard buttons. It never evaluates downloaded content.
- Downloads are inert files. The page instructs users to verify SHA-256
  checksums **before** running anything and provides
  `tools/verify_checksums.sh`, which only computes and compares hashes.
- Releases are built by `tools/build_release.sh`, which stages a clean
  payload (no `__pycache__`, no local configs, no credentials) and publishes
  `SHA256SUMS.txt` next to the artifacts.

## 11. Threat model (summary)

| Threat | Mitigation |
|---|---|
| Tool runs without user intent | No auto-execution anywhere; explicit CLI invocation required |
| Data leaves host unnoticed | Approval gates for send; `--no-send`; SMTP off by default; audited DENY/OK outcomes |
| Credential theft by the tool itself | Env-only credentials, never persisted or logged; denylisted browser prefs |
| Report leakage | `0600`/`0700` permissions, CONFIDENTIAL classification header, operator-controlled storage |
| Tampered download | Published SHA-256 checksums + verifier script + readable Bash source |
| Silent scope creep | Config-validated scope, hidden-file exclusion, depth/size limits, audit of every skip |
| Supply-chain (Python) | Standard library only — zero third-party Python dependencies |

## 12. Reporting a vulnerability

If you find a security or privacy issue in LFC, please report it to the
project maintainer **privately** before any public disclosure, including:

- affected version / commit,
- reproduction steps,
- impact (what data could be collected, exposed or transmitted),
- suggested fix, if any.

Do not attach real forensic reports or credentials to the report.

## 13. Operator responsibilities

- Run LFC only on systems you are **authorized** to audit.
- Treat every generated report as CONFIDENTIAL system detail.
- Review `audit.log` before sharing anything from the output directory.
- Delete reports when they are no longer needed.
- Keep `smtp.enabled=false` unless delivery is genuinely required.
