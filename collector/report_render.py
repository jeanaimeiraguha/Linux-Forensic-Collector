"""HTML and plain-text renderers for LFC reports.

Both renderers consume only the structured report dictionary built by
``report_processor.build_report`` and escape every dynamic value.
"""

from __future__ import annotations

import html
from typing import Any, Iterable

from .fragments import human_bytes

CSS = """
:root{--ink:#16213e;--muted:#5c6b84;--line:#dfe5ef;--bg:#f4f6fb;--card:#fff;
--accent:#0b6e4f;--accent2:#0f4c81;--warn:#b26a00;--err:#b3261e;--hdr:#10233f}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
background:var(--bg);color:var(--ink);line-height:1.5;font-size:15px}
header{background:var(--hdr);color:#fff;padding:26px 32px;border-bottom:4px solid var(--accent)}
header h1{margin:0;font-size:26px;letter-spacing:.3px}
header .sub{opacity:.85;margin-top:6px;font-size:14px}
.badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;
font-weight:700;letter-spacing:.6px;text-transform:uppercase}
.badge.classification{background:#ffb4a2;color:#5c1010}
.badge.ok{background:#d9f2e6;color:#0b6e4f}
.badge.warn{background:#fdecc8;color:#8a5a00}
.badge.err{background:#f9d6d2;color:#b3261e}
.wrap{max-width:1180px;margin:0 auto;padding:24px}
nav.toc{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:14px 18px;margin:20px 0;display:flex;flex-wrap:wrap;gap:8px 16px;font-size:14px}
nav.toc a{color:var(--accent2);text-decoration:none;font-weight:600}
nav.toc a:hover{text-decoration:underline}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:20px 22px;margin:18px 0}
section h2{margin:0 0 4px;font-size:19px;color:var(--hdr)}
section h3{margin:20px 0 8px;font-size:15px;color:var(--accent2);text-transform:uppercase;letter-spacing:.5px}
.lead{color:var(--muted);font-size:13px;margin:0 0 14px}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:12px;margin:14px 0 4px}
.card{background:#f8fafd;border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.card .v{font-size:22px;font-weight:700;color:var(--hdr)}
.card .k{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px}
table{width:100%;border-collapse:collapse;font-size:13.5px;margin:8px 0}
th,td{border-bottom:1px solid var(--line);padding:7px 9px;text-align:left;vertical-align:top}
th{background:#eef2f8;font-size:12px;text-transform:uppercase;letter-spacing:.4px;color:var(--muted)}
tbody tr:nth-child(even){background:#fafbfd}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.mono,code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
font-size:12.5px;word-break:break-all}
.kv td:first-child{width:280px;color:var(--muted);font-weight:600}
.note{background:#eef7f2;border-left:4px solid var(--accent);padding:10px 14px;
margin:12px 0;font-size:13.5px;border-radius:0 6px 6px 0}
.note.warn{background:#fff7e8;border-left-color:var(--warn)}
.note.err{background:#fdeeed;border-left-color:var(--err)}
ul.tight{margin:8px 0;padding-left:22px}
ul.tight li{margin:3px 0}
footer{color:var(--muted);font-size:13px;padding:20px 32px 34px;text-align:center}
.pill{display:inline-block;background:#eef2f8;border:1px solid var(--line);
border-radius:6px;padding:1px 7px;font-size:12px;margin:1px 4px 1px 0}
@media print{body{background:#fff}section{break-inside:avoid;border-color:#bbb}
nav.toc{display:none}}
"""


def esc(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _table(headers: list[str], rows: Iterable[Iterable[Any]], empty: str = "None") -> str:
    rows = list(rows)
    if not rows:
        return f'<p class="lead">{esc(empty)}</p>'
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = []
    for row in rows:
        cells = "".join(
            f"<td>{cell if isinstance(cell, str) and cell.startswith('<span') else esc(cell)}</td>"
            for cell in row
        )
        body.append(f"<tr>{cells}</tr>")
    return (
        f"<div style=\"overflow-x:auto\"><table><thead><tr>{head}</tr></thead>"
        f"<tbody>{''.join(body)}</tbody></table></div>"
    )


def _kv(pairs: list[tuple[str, Any]]) -> str:
    if not pairs:
        return '<p class="lead">None</p>'
    rows = "".join(
        f"<tr><td>{esc(k)}</td><td class='mono'>{esc(v)}</td></tr>" for k, v in pairs
    )
    return (
        '<div style="overflow-x:auto"><table class="kv"><tbody>'
        f"{rows}</tbody></table></div>"
    )


def _card(value: Any, label: str) -> str:
    return f'<div class="card"><div class="v">{esc(value)}</div><div class="k">{esc(label)}</div></div>'


def _badge(text: str, kind: str = "ok") -> str:
    return f'<span class="badge {kind}">{esc(text)}</span>'


def _fmt_bytes(value: Any) -> str:
    try:
        return human_bytes(float(value))
    except (TypeError, ValueError):
        return str(value)


def render_html(report: dict[str, Any]) -> str:
    info = report["report"]
    system = report["system"]
    general = system.get("general", {})
    detect = system.get("detect", {})
    fs = report["filesystem"]
    media = report["media"]
    browser = report["browser"]
    network = report["network"]
    software = report["software"]
    coll = report["collection"]
    privacy = report["privacy"]

    cards = "".join(
        [
            _card(fs.get("inventory_total", 0), "Files inventoried"),
            _card(_fmt_bytes(fs.get("summary", {}).get("total_bytes", 0)), "Total size"),
            _card(media.get("total", 0), "Media files"),
            _card(fs.get("large_file_count", 0), "Large files"),
            _card(software.get("package_count", 0), "Packages"),
            _card(len(network.get("interfaces", [])), "Network ifaces"),
            _card(coll.get("skipped_count", 0), "Skipped ops"),
            _card(coll.get("errors_count", 0), "Errors"),
        ]
    )

    toc_items = [
        ("sec-system", "System"),
        ("sec-filesystem", "Filesystem"),
        ("sec-media", "Media"),
        ("sec-browser", "Browser audit"),
        ("sec-network", "Network"),
        ("sec-software", "Software"),
        ("sec-collection", "Collection notes"),
        ("sec-privacy", "Privacy"),
    ]
    toc = "".join(f'<a href="#{i}">{esc(t)}</a>' for i, t in toc_items)

    # --- system ------------------------------------------------------------
    general_pairs = [
        (k.replace("_", " ").title(), v)
        for k, v in sorted(general.items())
        if k != "hostnamectl"
    ]
    cpu_pairs = [(k.replace("_", " ").title(), v) for k, v in sorted(system.get("cpu", {}).items())]
    mem_rows = [
        (m.get("type"), m.get("total_human"), m.get("available_kb"), m.get("used_kb"))
        for m in system.get("memory", [])
    ]
    storage_rows = [
        (s.get("device"), s.get("size"), s.get("type"), s.get("model"),
         s.get("transport"), s.get("rotational"))
        for s in system.get("storage", [])
    ]
    fsdev_rows = [
        (f.get("device"), f.get("mount"), f.get("fstype"), f.get("size"),
         f.get("used"), f.get("avail"), f.get("use_percent"))
        for f in system.get("filesystems", [])
    ]
    system_html = f"""
<section id="sec-system"><h2>System Intelligence</h2>
<p class="lead">Distribution, kernel, hardware and resource state at collection time.</p>
{_kv(general_pairs)}
<h3>Processor</h3>{_kv(cpu_pairs)}
<h3>Memory &amp; Swap</h3>
{_table(["Type", "Total", "Available (kB)", "Used (kB)"], mem_rows)}
<h3>Storage Devices</h3>
{_table(["Device", "Size", "Type", "Model", "Transport", "Rotational"], storage_rows)}
<h3>Mounted Filesystems</h3>
{_table(["Device", "Mount", "FSType", "Size", "Used", "Avail", "Use%"], fsdev_rows)}
</section>"""

    # --- filesystem --------------------------------------------------------
    cat_rows = [
        (c.get("category"), c.get("count"), c.get("bytes_human"))
        for c in fs.get("top_categories", [])
    ]
    large_rows = [
        (lf.get("path"), lf.get("size_human"), lf.get("mtime_utc"), lf.get("category"))
        for lf in fs.get("large_files", [])[:200]
    ]
    summary_pairs = [
        (k.replace("_", " ").title(), v) for k, v in sorted(fs.get("summary", {}).items())
    ]
    trunc_note = (
        '<div class="note warn">Large-file list truncated for display — '
        "see <code>system_report.json</code> for the full list.</div>"
        if fs.get("large_file_count", 0) > 200
        else ""
    )
    filesystem_html = f"""
<section id="sec-filesystem"><h2>Filesystem Inventory</h2>
<p class="lead">Metadata only (path, size, timestamp, type). File contents were not read.</p>
{_kv(summary_pairs)}
<h3>Contents by Category</h3>
{_table(["Category", "Files", "Size"], cat_rows, "No files inventoried")}
<h3>Unusually Large Files (&gt; {esc(fs.get('large_file_threshold_mb', 500))} MiB)</h3>
{_table(["Path", "Size", "Modified (UTC)", "Category"], large_rows, "None detected")}
{trunc_note}
<div class="note">Full inventories: <code>filesystem_inventory.csv</code>
({esc(fs.get('inventory_total', 0))} rows) and <code>media_inventory.csv</code>.</div>
</section>"""

    # --- media -------------------------------------------------------------
    media_counts = media.get("counts", {})
    media_rows_html = _table(
        ["Category", "Files"],
        sorted(media_counts.items(), key=lambda kv: kv[1], reverse=True),
        "No media files found",
    )
    media_html = f"""
<section id="sec-media"><h2>Media Inventory</h2>
<p class="lead">Documents, images, video and audio identified by extension — metadata only.</p>
{_card(media.get("total", 0), "Media files")}
{_card(media.get("total_bytes_human", "0 B"), "Combined size")}
<h3>By Category</h3>{media_rows_html}
<div class="detail-note"></div>
</section>"""

    # --- browser -----------------------------------------------------------
    install_rows = [
        (b.get("browser"), b.get("installed"), b.get("version") or "-",
         b.get("package_version") or "-", b.get("source"))
        for b in browser.get("installs", [])
    ]
    profile_rows = [
        (p.get("browser"), p.get("profile_name"), p.get("profile_path"))
        for p in browser.get("profiles", [])
    ]
    prefs_html_parts = []
    for bname, profiles in (browser.get("security_preferences") or {}).items():
        for pname, pdata in profiles.items():
            prefs = pdata.get("prefs", {})
            prefs_html_parts.append(
                f"<h3>{esc(bname)} / {esc(pname)}</h3>"
                + _kv(sorted(prefs.items()))
            )
    prefs_html = "".join(prefs_html_parts) or '<p class="lead">No allowlisted security preferences found.</p>'
    not_accessed = browser.get("not_accessed", [])
    browser_html = f"""
<section id="sec-browser"><h2>Browser Security Audit</h2>
<p class="lead">Installation, version, profile locations and allowlisted security settings.</p>
<div class="note">Credentials, cookies, tokens, keys and account data were
<strong>never opened, decrypted or exported</strong>.</div>
<h3>Installations</h3>
{_table(["Browser", "Installed", "Version", "Package version", "Source"], install_rows)}
<h3>Profiles</h3>
{_table(["Browser", "Profile", "Path"], profile_rows, "No browser profiles found")}
<h3>Allowlisted Security Preferences</h3>{prefs_html}
<h3>Explicitly Not Accessed</h3>
<ul class="tight">{''.join(f'<li>{esc(i)}</li>' for i in not_accessed)}</ul>
</section>"""

    # --- network -----------------------------------------------------------
    iface_rows = [
        (i.get("iface"), i.get("operstate"), i.get("mtu"), i.get("flags"))
        for i in network.get("interfaces", [])
    ]
    addr_rows = [
        (a.get("iface"), a.get("family"), a.get("scope"), a.get("address"))
        for a in network.get("addresses", [])
    ]
    route_rows = [
        (r.get("destination"), r.get("gateway"), r.get("device"), r.get("protocol"))
        for r in network.get("routes", [])
    ]
    dns_rows = [(d.get("source"), d.get("server")) for d in network.get("dns", [])]
    conn_rows = [
        (c.get("protocol"), c.get("state"), c.get("local_address"),
         c.get("peer_address"), c.get("process") or "-")
        for c in network.get("connections", [])[:100]
    ]
    fw_rows = [
        (f.get("backend"), f.get("status"), f.get("detail"))
        for f in network.get("firewall", [])
    ]
    adapter_rows = [
        (a.get("iface"), a.get("driver"), a.get("version"), a.get("firmware"))
        for a in network.get("adapters", [])
    ]
    excl = network.get("exclusions", [])
    network_html = f"""
<section id="sec-network"><h2>Network Audit</h2>
<p class="lead">Configuration and connection metadata only — no packet capture or credential capture.</p>
<h3>Interfaces</h3>
{_table(["Interface", "State", "MTU", "Flags"], iface_rows, "None detected")}
<h3>Addresses</h3>
{_table(["Interface", "Family", "Scope", "Address"], addr_rows, "None")}
<h3>Routes</h3>
{_table(["Destination", "Gateway", "Device", "Protocol"], route_rows, "None")}
<h3>DNS</h3>
{_table(["Source", "Server"], dns_rows, "None")}
<h3>Firewall</h3>
{_table(["Backend", "Status", "Detail"], fw_rows, "Not detected")}
<h3>Adapter Drivers</h3>
{_table(["Interface", "Driver", "Version", "Firmware"], adapter_rows, "Not available")}
<h3>Active Connections (first {min(100, network.get('connections_total', 0))} of {esc(network.get('connections_total', 0))})</h3>
{_table(["Proto", "State", "Local", "Peer", "Process"], conn_rows, "None")}
<div class="note">Exclusions: {'; '.join(esc(f"{e.get('item')} — {e.get('status')}") for e in excl) or 'n/a'}</div>
</section>"""

    # --- software ----------------------------------------------------------
    mgr_rows = [
        (m.get("manager"), m.get("available"), m.get("path") or "-")
        for m in software.get("managers", [])
    ]
    svc_rows = [
        (s.get("unit"), s.get("state")) for s in software.get("services", [])[:200]
    ]
    pkg_rows = [
        (p.get("name"), p.get("version"), p.get("manager"))
        for p in software.get("packages", [])[:300]
    ]
    pkg_note = (
        '<div class="note warn">Showing first 300 packages — '
        f"full list is in <code>system_report.json</code> "
        f"({esc(software.get('package_count', 0))} total).</div>"
        if software.get("package_count", 0) > 300
        else ""
    )
    software_html = f"""
<section id="sec-software"><h2>Installed Software</h2>
<p class="lead">Package inventory and service state from the native package manager.</p>
{_card(software.get("package_count", 0), "Packages")}
{_card(software.get("services_total", 0), "Service entries")}
<h3>Package Managers</h3>
{_table(["Manager", "Available", "Path"], mgr_rows)}
<h3>Packages</h3>{pkg_rows and _table(["Name", "Version", "Manager"], pkg_rows) or '<p class="lead">None</p>'}
{pkg_note}
<h3>Services</h3>
{_table(["Unit", "State"], svc_rows, "None")}
</section>"""

    # --- collection notes --------------------------------------------------
    err_rows = [
        (e.get("module"), e.get("operation"), e.get("message"))
        for e in coll.get("errors", [])
    ]
    skip_rows = [
        (s.get("module"), s.get("operation"), s.get("reason"))
        for s in coll.get("skipped", [])
    ]
    tool_rows = [
        (t.get("command"), t.get("available"), t.get("fallback"))
        for t in coll.get("tools", [])
        if t.get("available") == "no"
    ]
    collection_html = f"""
<section id="sec-collection"><h2>Collection Notes</h2>
<p class="lead">Scope, skipped operations, errors and unavailable tooling.</p>
<h3>Run Details</h3>
{_kv([
    ("Scope", ", ".join(info.get("scope", [])) or "n/a"),
    ("Modules run", ", ".join(info.get("modules_run", [])) or "n/a"),
    ("Duration (s)", info.get("duration_seconds", 0)),
    ("Output directory", info.get("output_dir", "")),
    ("Audit log", info.get("audit_log", "audit.log")),
])}
<h3>Skipped Operations ({esc(coll.get('skipped_count', 0))})</h3>
{_table(["Module", "Operation", "Reason"], skip_rows, "None")}
<h3>Errors ({esc(coll.get('errors_count', 0))})</h3>
{_table(["Module", "Operation", "Message"], err_rows, "None")}
<h3>Unavailable Commands</h3>
{_table(["Command", "Available", "Fallback"], tool_rows, "All detected commands available")}
</section>"""

    # --- privacy -----------------------------------------------------------
    privacy_html = f"""
<section id="sec-privacy"><h2>Security &amp; Privacy Statement</h2>
<ul class="tight">{''.join(f'<li>{esc(n)}</li>' for n in privacy.get("notes", []))}</ul>
{_kv([
    ("File contents collected", "No" if not privacy.get("file_contents_collected") else "Yes"),
    ("Credentials collected", "No" if not privacy.get("credentials_collected") else "Yes"),
    ("Packet capture", "No" if not privacy.get("packet_capture") else "Yes"),
    ("Persistence installed", "No" if not privacy.get("persistence_installed") else "Yes"),
    ("Transmission requires approval", "Yes" if privacy.get("transmission_requires_approval") else "No"),
])}
</section>"""

    footer_text = info.get("contact", "") or ""

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LFC Report — {esc(info.get('hostname', ''))} — {esc(info.get('generated_at', ''))}</title>
<style>{CSS}</style></head>
<body>
<header>
  <h1>Linux Forensic Collector — System Report</h1>
  <div class="sub">
    Host <strong>{esc(info.get('hostname', 'unknown'))}</strong>
    &nbsp;·&nbsp; {esc(info.get('generated_at', ''))}
    &nbsp;·&nbsp; v{esc(info.get('tool_version', ''))}
    &nbsp;·&nbsp; <span class="badge classification">{esc(info.get('classification', 'CONFIDENTIAL'))}</span>
  </div>
</header>
<div class="wrap">
  <nav class="toc">{toc}</nav>
  <section><h2>Collection Overview</h2>
  <p class="lead">Generated by {esc(info.get('tool', ''))} — review before approving any transmission.</p>
  <div class="cards">{cards}</div>
  {_kv([
      ("Organization", info.get("org_name", "")),
      ("Contact", info.get("contact", "")),
      ("Scope", ", ".join(info.get("scope", [])) or "n/a"),
      ("Modules", ", ".join(info.get("modules_run", [])) or "n/a"),
      ("Duration", f"{info.get('duration_seconds', 0)}s"),
  ])}
  </section>
  {system_html}
  {filesystem_html}
  {media_html}
  {browser_html}
  {network_html}
  {software_html}
  {collection_html}
  {privacy_html}
</div>
<footer>
  {esc(info.get('company_footer', ''))}<br>
  {footer_text}<br>
  Report classification: <strong>{esc(info.get('classification', ''))}</strong>
</footer>
</body></html>
"""


def _rule(char: str = "-", width: int = 72) -> str:
    return char * width


def _txt_table(headers: list[str], rows: Iterable[Iterable[Any]], empty: str = "None") -> str:
    rows = [[("" if c is None else str(c)) for c in row] for row in rows]
    if not rows:
        return f"  {empty}"
    all_rows = [headers] + rows
    widths = [0] * len(headers)
    for row in all_rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], min(len(cell), 60))
    def fmt(row: list[str]) -> str:
        cells = []
        for i, cell in enumerate(row[: len(headers)]):
            text = cell if len(cell) <= widths[i] else cell[: widths[i] - 3] + "..."
            cells.append(text.ljust(widths[i]))
        return "  " + "  ".join(cells).rstrip()
    out = [fmt(headers), "  " + "  ".join("-" * w for w in widths)]
    out.extend(fmt(r) for r in rows)
    return "\n".join(out)


def render_text(report: dict[str, Any]) -> str:
    info = report["report"]
    system = report["system"]
    fs = report["filesystem"]
    media = report["media"]
    browser = report["browser"]
    network = report["network"]
    software = report["software"]
    coll = report["collection"]
    privacy = report["privacy"]
    general = system.get("general", {})

    L: list[str] = []
    add = L.append

    add(_rule("="))
    add(f" {info.get('tool', '')} v{info.get('tool_version', '')} - SYSTEM REPORT")
    add(_rule("="))
    add(f" Host            : {info.get('hostname', '')}")
    add(f" Generated (UTC) : {info.get('generated_at', '')}")
    add(f" Classification  : {info.get('classification', '')}")
    add(f" Organization    : {info.get('org_name', '')}")
    add(f" Scope           : {', '.join(info.get('scope', [])) or 'n/a'}")
    add(f" Modules         : {', '.join(info.get('modules_run', [])) or 'n/a'}")
    add(f" Duration        : {info.get('duration_seconds', 0)}s")
    add("")

    add(_rule())
    add(" 1. SYSTEM INTELLIGENCE")
    add(_rule())
    for key in (
        "distro_pretty", "distro_version", "kernel", "arch", "hostname",
        "hardware_vendor", "hardware_product", "uptime_seconds", "init_system",
        "package_manager", "elevated",
    ):
        value = general.get(key) or system.get("detect", {}).get(key, "")
        if value:
            add(f"  {key.replace('_', ' ').ljust(22)}: {value}")
    cpu = system.get("cpu", {})
    for key in ("model", "logical_cpus", "mhz"):
        if cpu.get(key):
            add(f"  {key.replace('_', ' ').ljust(22)}: {cpu[key]}")
    add("")
    add("  Memory:")
    add(_txt_table(
        ["Type", "Total", "Avail kB", "Used kB"],
        [(m.get("type"), m.get("total_human"), m.get("available_kb"), m.get("used_kb"))
         for m in system.get("memory", [])],
    ))
    add("")
    add("  Filesystems:")
    add(_txt_table(
        ["Device", "Mount", "Type", "Size", "Use%"],
        [(f.get("device"), f.get("mount"), f.get("fstype"), f.get("size"), f.get("use_percent"))
         for f in system.get("filesystems", [])],
    ))
    add("")

    add(_rule())
    add(" 2. FILESYSTEM INVENTORY (metadata only)")
    add(_rule())
    summary = fs.get("summary", {})
    add(f"  Files inventoried : {fs.get('inventory_total', 0)}")
    add(f"  Directories       : {summary.get('directories_listed', '0')}")
    add(f"  Total size        : {_fmt_bytes(summary.get('total_bytes', 0))}")
    add(f"  Large files       : {fs.get('large_file_count', 0)} "
        f"(threshold {fs.get('large_file_threshold_mb', 500)} MiB)")
    add("  Contents collected: NO - metadata only")
    add("")
    add("  Top categories:")
    for cat in fs.get("top_categories", [])[:12]:
        add(f"    {str(cat.get('category')).ljust(14)} {str(cat.get('count')).rjust(8)} files "
            f"{cat.get('bytes_human', '')}".rstrip())
    add("")
    add("  Largest files:")
    for lf in fs.get("large_files", [])[:50]:
        add(f"    {lf.get('size_human', '').rjust(10)}  {lf.get('mtime_utc', '')}  {lf.get('path', '')}")
    if fs.get("large_file_count", 0) > 50:
        add(f"    ... {fs['large_file_count'] - 50} more (see system_report.json)")
    add("")

    add(_rule())
    add(" 3. MEDIA INVENTORY")
    add(_rule())
    add(f"  Media files : {media.get('total', 0)} ({media.get('total_bytes_human', '0 B')})")
    for cat, count in sorted(media.get("counts", {}).items(), key=lambda kv: kv[1], reverse=True):
        add(f"    {cat.ljust(14)} {count}")
    add("")

    add(_rule())
    add(" 4. BROWSER SECURITY AUDIT")
    add(_rule())
    add(_txt_table(
        ["Browser", "Installed", "Version", "Package"],
        [(b.get("browser"), b.get("installed"), b.get("version") or "-",
          b.get("package_version") or "-")
         for b in browser.get("installs", [])],
    ))
    add("")
    add("  Allowlisted security preferences:")
    prefs_any = False
    for bname, profiles in (browser.get("security_preferences") or {}).items():
        for pname, pdata in profiles.items():
            for key, value in sorted(pdata.get("prefs", {}).items()):
                add(f"    {bname}/{pname}: {key} = {value}")
                prefs_any = True
    if not prefs_any:
        add("    (none found)")
    add("")
    add("  Explicitly NOT accessed:")
    for item in browser.get("not_accessed", []):
        add(f"    - {item}")
    add("")

    add(_rule())
    add(" 5. NETWORK AUDIT (metadata only)")
    add(_rule())
    add(_txt_table(
        ["Interface", "State", "MTU"],
        [(i.get("iface"), i.get("operstate"), i.get("mtu"))
         for i in network.get("interfaces", [])],
    ))
    add("")
    add("  Firewall:")
    add(_txt_table(
        ["Backend", "Status", "Detail"],
        [(f.get("backend"), f.get("status"), f.get("detail"))
         for f in network.get("firewall", [])],
    ))
    add(f"  Active connections recorded: {network.get('connections_total', 0)} "
        f"(showing {min(50, network.get('connections_total', 0))})")
    add(_txt_table(
        ["Proto", "State", "Local", "Peer"],
        [(c.get("protocol"), c.get("state"), c.get("local_address"), c.get("peer_address"))
         for c in network.get("connections", [])[:50]],
    ))
    add("")

    add(_rule())
    add(" 6. INSTALLED SOFTWARE")
    add(_rule())
    add(f"  Packages : {software.get('package_count', 0)}")
    add(f"  Services : {software.get('services_total', 0)}")
    add("  First 40 packages:")
    add(_txt_table(
        ["Name", "Version"],
        [(p.get("name"), p.get("version")) for p in software.get("packages", [])[:40]],
    ))
    add("")

    add(_rule())
    add(" 7. COLLECTION NOTES")
    add(_rule())
    add(f"  Skipped operations : {coll.get('skipped_count', 0)}")
    for row in coll.get("skipped", [])[:40]:
        add(f"    [skip] {row.get('module')}/{row.get('operation')}: {row.get('reason')}")
    if coll.get("skipped_count", 0) > 40:
        add(f"    ... {coll['skipped_count'] - 40} more")
    add(f"  Errors             : {coll.get('errors_count', 0)}")
    for row in coll.get("errors", [])[:40]:
        add(f"    [err ] {row.get('module')}/{row.get('operation')}: {row.get('message')}")
    add("")

    add(_rule())
    add(" 8. PRIVACY STATEMENT")
    add(_rule())
    for note in privacy.get("notes", []):
        add(f"  * {note}")
    add("")
    add(_rule("="))
    add(f" End of report - classification: {info.get('classification', '')}")
    add(_rule("="))
    add("")
    return "\n".join(L)
