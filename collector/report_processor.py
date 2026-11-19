"""Builds LFC reports (JSON, HTML, TXT, CSV) from Bash collection fragments.

The processor is deliberately passive: it reads TSV fragments written by the
collection modules, applies validation/limits from the configuration and
emits the five deliverable report files. It never gathers new system data.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .browser_prefs import inspect_profiles
from .config import ConfigError, load_config, require_valid
from .fragments import (
    RawData,
    epoch_to_iso,
    human_bytes,
    load_raw,
    write_csv,
)

DELIVERABLES = (
    "system_report.html",
    "system_report.json",
    "system_report.txt",
    "filesystem_inventory.csv",
    "media_inventory.csv",
)

PRIVACY_NOTES = [
    "File contents were NOT read, copied or transmitted - metadata only.",
    "Passwords, cookies, session tokens, private keys and account "
    "credentials were NOT accessed.",
    "No packet capture, traffic interception or credential capture was performed.",
    "No persistence, auto-start or background upload mechanisms were installed.",
    "Reports are only transmitted after explicit operator approval.",
]


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _int_or(value: Any, default: int = 0) -> int:
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return default


def _summarise_categories(inv_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    counts: dict[str, dict[str, int]] = {}
    for row in inv_rows:
        cat = row.get("category", "other")
        entry = counts.setdefault(cat, {"category": cat, "count": 0, "bytes": 0})
        entry["count"] += 1
        entry["bytes"] += _int_or(row.get("size_bytes", 0))
    out = sorted(counts.values(), key=lambda e: e["bytes"], reverse=True)
    for entry in out:
        entry["bytes_human"] = human_bytes(entry["bytes"])
    return out


def _sample(rows: list[dict[str, str]], limit: int = 200) -> list[dict[str, str]]:
    return rows[:limit]


def build_report(
    raw: RawData,
    cfg: dict[str, Any],
    meta: dict[str, Any],
) -> dict[str, Any]:
    """Assemble the structured report dictionary."""
    general = raw.kv.get("system.general", {})
    detect = raw.kv.get("detect", {})
    hostname = general.get("hostname") or detect.get("hostname", "unknown")

    inv_rows = raw.table("filesystem.inventory")
    media_rows = raw.table("media.inventory")
    large_threshold = _int_or(
        raw.kv.get("filesystem.summary", {}).get("large_file_threshold_mb", 500), 500
    )

    large_files = []
    for row in inv_rows:
        if row.get("flags") == "LARGE":
            size = _int_or(row.get("size_bytes", 0))
            large_files.append(
                {
                    "path": row.get("path", ""),
                    "size_bytes": size,
                    "size_human": human_bytes(size),
                    "mtime_utc": epoch_to_iso(row.get("mtime_epoch", "")),
                    "category": row.get("category", ""),
                }
            )
    large_files.sort(key=lambda e: e["size_bytes"], reverse=True)
    large_files = large_files[:1000]

    json_limit = _int_or(cfg["collection"].get("json_max_inventory_rows", 5000), 5000)
    include_full = bool(cfg["report"].get("include_full_inventory_in_json", False))
    inv_for_json = inv_rows[:json_limit] if include_full else []

    # Convert epoch fields to ISO for JSON readability.
    for row in inv_for_json:
        row["mtime_utc"] = epoch_to_iso(row.get("mtime_epoch", ""))

    media_counts: dict[str, int] = {}
    media_bytes = 0
    for row in media_rows:
        cat = row.get("category", "other")
        media_counts[cat] = media_counts.get(cat, 0) + 1
        media_bytes += _int_or(row.get("size_bytes", 0))

    packages = raw.table("software.packages")
    services = raw.table("software.services")

    browser_profiles = raw.table("browser.profiles")
    try:
        security_prefs = inspect_profiles(browser_profiles)
    except Exception:  # pragma: no cover — prefs parsing must never abort a report
        security_prefs = {}

    errors = raw.table("errors")
    skipped = raw.table("skipped")

    report: dict[str, Any] = {
        "report": {
            "tool": "Linux Forensic Collector (LFC)",
            "tool_version": __version__,
            "generated_at": _now_iso(),
            "hostname": hostname,
            "classification": cfg["meta"].get("report_classification", "CONFIDENTIAL"),
            "org_name": cfg["meta"].get("org_name", ""),
            "contact": cfg["meta"].get("report_contact", ""),
            "scope": list(meta.get("scope", [])),
            "modules_run": list(meta.get("modules_run", [])),
            "duration_seconds": _int_or(meta.get("duration_seconds", 0)),
            "output_dir": str(meta.get("output_dir", "")),
            "audit_log": "audit.log",
            "company_footer": cfg["report"].get("company_footer", ""),
        },
        "system": {
            "general": general,
            "detect": detect,
            "cpu": raw.kv.get("system.cpu", {}),
            "memory": raw.table("system.memory"),
            "storage": raw.table("system.storage"),
            "filesystems": raw.table("system.filesystems"),
        },
        "filesystem": {
            "summary": raw.kv.get("filesystem.summary", {}),
            "inventory_total": len(inv_rows),
            "inventory_included_in_json": len(inv_for_json),
            "inventory_truncated": len(inv_for_json) < len(inv_rows),
            "large_file_threshold_mb": large_threshold,
            "large_files": large_files,
            "large_file_count": len(large_files),
            "top_categories": _summarise_categories(inv_rows),
            "inventory": inv_for_json,
        },
        "media": {
            "summary": raw.kv.get("media.summary", {}),
            "total": len(media_rows),
            "total_bytes": media_bytes,
            "total_bytes_human": human_bytes(media_bytes),
            "counts": media_counts,
            "inventory": media_rows[:json_limit] if include_full else [],
        },
        "browser": {
            "installs": raw.table("browser.installs"),
            "profiles": browser_profiles,
            "security_preferences": security_prefs,
            "not_accessed": [
                row.get("item", "")
                for row in raw.table("browser.not_accessed")
            ],
        },
        "network": {
            "interfaces": raw.table("network.interfaces"),
            "addresses": raw.table("network.addresses"),
            "routes": raw.table("network.routes"),
            "dns": raw.table("network.dns"),
            "connections": _sample(raw.table("network.connections"), 500),
            "connections_total": len(raw.table("network.connections")),
            "firewall": raw.table("network.firewall"),
            "adapters": raw.table("network.adapters"),
            "exclusions": [
                {"item": row.get("item", ""), "status": row.get("status", "")}
                for row in raw.table("network.exclusions")
            ],
        },
        "software": {
            "managers": raw.table("software.managers"),
            "package_count": len(packages),
            "packages": packages[:json_limit] if include_full else _sample(packages, 500),
            "packages_truncated": (not include_full) and len(packages) > 500,
            "services": _sample(services, 500),
            "services_total": len(services),
            "summary": raw.kv.get("software.summary", {}),
        },
        "collection": {
            "started_at": str(meta.get("started_at", "")),
            "errors": errors,
            "errors_count": len(errors),
            "skipped": skipped,
            "skipped_count": len(skipped),
            "tools": raw.table("tools"),
        },
        "privacy": {
            "file_contents_collected": False,
            "credentials_collected": False,
            "packet_capture": False,
            "persistence_installed": False,
            "transmission_requires_approval": True,
            "notes": PRIVACY_NOTES,
        },
    }
    return report


def write_reports(report: dict[str, Any], out_dir: Path, raw: RawData) -> dict[str, int]:
    """Write all deliverable files; returns {filename: bytes}."""
    out_dir.mkdir(parents=True, exist_ok=True)
    sizes: dict[str, int] = {}

    # --- CSV deliverables ---------------------------------------------------
    inv_rows = raw.table("filesystem.inventory")
    inv_csv_fields = [
        "category",
        "path",
        "size_bytes",
        "mtime_epoch",
        "mtime_utc",
        "extension",
        "flags",
    ]
    inv_csv_rows = []
    for row in inv_rows:
        item = dict(row)
        item["mtime_utc"] = epoch_to_iso(row.get("mtime_epoch", ""))
        inv_csv_rows.append(item)
    write_csv(inv_csv_rows, inv_csv_fields, out_dir / "filesystem_inventory.csv")

    media_rows = raw.table("media.inventory")
    media_csv_rows = []
    for row in media_rows:
        item = dict(row)
        item["mtime_utc"] = epoch_to_iso(row.get("mtime_epoch", ""))
        media_csv_rows.append(item)
    write_csv(media_csv_rows, inv_csv_fields, out_dir / "media_inventory.csv")

    # --- JSON ---------------------------------------------------------------
    json_path = out_dir / "system_report.json"
    json_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n",
        encoding="utf-8",
    )

    # --- HTML / TXT ---------------------------------------------------------
    from .report_render import render_html, render_text

    html_path = out_dir / "system_report.html"
    html_path.write_text(render_html(report), encoding="utf-8")

    txt_path = out_dir / "system_report.txt"
    txt_path.write_text(render_text(report), encoding="utf-8")

    for name in DELIVERABLES:
        path = out_dir / name
        sizes[name] = path.stat().st_size if path.exists() else 0
    return sizes


def print_summary(report: dict[str, Any], sizes: dict[str, int], out_dir: Path) -> None:
    """Human-readable collection summary (stdout)."""
    info = report["report"]
    fs = report["filesystem"]
    summary = fs.get("summary", {})
    total_bytes = _int_or(summary.get("total_bytes", 0))
    lines = [
        "",
        "=" * 66,
        f" {info['tool']} v{info['tool_version']} - Collection Summary",
        "=" * 66,
        f"  Host..............: {info['hostname']}",
        f"  Generated.........: {info['generated_at']}",
        f"  Classification....: {info['classification']}",
        f"  Scope.............: {', '.join(info['scope']) or 'n/a'}",
        f"  Modules...........: {', '.join(info['modules_run']) or 'n/a'}",
        f"  Duration..........: {info['duration_seconds']}s",
        "-" * 66,
        f"  Files inventoried.: {fs['inventory_total']} "
        f"({human_bytes(total_bytes)})",
        f"  Directories.......: {summary.get('directories_listed', '0')}",
        f"  Large files (>{fs['large_file_threshold_mb']} MiB): {fs['large_file_count']}",
        f"  Media files.......: {report['media']['total']} "
        f"({report['media']['total_bytes_human']})",
        f"  Packages..........: {report['software']['package_count']}",
        f"  Services..........: {report['software']['services_total']}",
        f"  Network ifaces....: {len(report['network']['interfaces'])}",
        f"  Browsers probed...: "
        f"{sum(1 for b in report['browser']['installs'] if b.get('installed') == 'yes')}",
        "-" * 66,
        f"  Skipped ops.......: {report['collection']['skipped_count']}",
        f"  Errors............: {report['collection']['errors_count']}",
        "-" * 66,
        "  Report files:",
    ]
    for name, size in sizes.items():
        lines.append(f"    - {name} ({human_bytes(size)})")
    lines += [
        "  Review the reports before approving any email transmission.",
        "=" * 66,
        "",
    ]
    print("\n".join(lines))


def process(
    raw_dir: str | Path,
    out_dir: str | Path,
    cfg_path: str | Path | None,
    meta: dict[str, Any],
) -> dict[str, Any]:
    """Full pipeline: load config + fragments, build and write reports."""
    cfg = load_config(cfg_path)
    require_valid(cfg)
    raw = load_raw(raw_dir)
    report = build_report(raw, cfg, meta)
    out = Path(out_dir)
    sizes = write_reports(report, out, raw)
    print_summary(report, sizes, out)
    return {"report": report, "sizes": sizes, "config": cfg}


def report_cli(argv: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="lfc report", description="Generate LFC reports from collected fragments"
    )
    parser.add_argument("--raw", required=True, help="raw fragment directory")
    parser.add_argument("--out", required=True, help="report output directory")
    parser.add_argument("--config", default=None, help="JSON config file")
    parser.add_argument("--scope", action="append", default=[], help="scope path (repeatable)")
    parser.add_argument("--modules", default="", help="comma-separated modules that ran")
    parser.add_argument("--duration", default="0", help="collection duration in seconds")
    parser.add_argument("--started-at", default="", help="collection start timestamp")
    args = parser.parse_args(argv)

    meta = {
        "scope": args.scope,
        "modules_run": [m for m in args.modules.split(",") if m],
        "duration_seconds": args.duration,
        "output_dir": args.out,
        "started_at": args.started_at,
    }
    try:
        process(args.raw, args.out, args.config, meta)
    except ConfigError as exc:
        print(str(exc), file=__import__("sys").stderr)
        return 3
    except Exception as exc:  # pragma: no cover
        print(f"report generation failed: {exc}", file=__import__("sys").stderr)
        return 1
    return 0
