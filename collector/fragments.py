"""Fragment (TSV) reader for LFC raw collection output.

The Bash engine writes tab-separated fragments with ``\\t``/``\\n``/``\\r``/
``\\\\`` escaping so that arbitrary file paths (including paths containing
tabs or newlines) survive the round trip. This module reverses that
escaping and exposes the fragments as plain Python structures.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def unescape(value: str) -> str:
    """Reverse the escaping applied by ``lfc_escape`` in lib/common.sh."""
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            nxt = value[i + 1]
            if nxt == "t":
                out.append("\t")
                i += 2
                continue
            if nxt == "n":
                out.append("\n")
                i += 2
                continue
            if nxt == "r":
                out.append("\r")
                i += 2
                continue
            if nxt == "\\":
                out.append("\\")
                i += 2
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def read_table(path: Path) -> list[dict[str, str]]:
    """Read a TSV fragment into a list of dicts (header row required)."""
    if not path.is_file():
        return []
    rows: list[dict[str, str]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lines = text.split("\n")
    if not lines or not lines[0].strip():
        return []
    headers = lines[0].split("\t")
    for line in lines[1:]:
        if not line:
            continue
        fields = line.split("\t")
        # Pad short rows so dict access never raises.
        if len(fields) < len(headers):
            fields = fields + [""] * (len(headers) - len(fields))
        row = {
            unescape(h): unescape(v)
            for h, v in zip(headers, fields)
        }
        rows.append(row)
    return rows


def read_kv(path: Path) -> dict[str, str]:
    """Read a two-column key/value TSV fragment into a dict."""
    if not path.is_file():
        return {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    out: dict[str, str] = {}
    lines = text.split("\n")
    for line in lines[1:]:  # skip header
        if not line:
            continue
        parts = line.split("\t", 1)
        key = unescape(parts[0])
        value = unescape(parts[1]) if len(parts) > 1 else ""
        out[key] = value
    return out


def kv_multi(path: Path) -> list[tuple[str, str]]:
    """Read a key/value fragment preserving duplicate keys (order kept)."""
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: list[tuple[str, str]] = []
    for line in text.split("\n")[1:]:
        if not line:
            continue
        parts = line.split("\t", 1)
        key = unescape(parts[0])
        value = unescape(parts[1]) if len(parts) > 1 else ""
        out.append((key, value))
    return out


@dataclass
class RawData:
    """All fragments from one collection run."""

    raw_dir: Path
    tables: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    kv: dict[str, dict[str, str]] = field(default_factory=dict)
    kv_multi: dict[str, list[tuple[str, str]]] = field(default_factory=dict)

    def table(self, name: str) -> list[dict[str, str]]:
        return self.tables.get(name, [])

    def kvget(self, table: str, key: str, default: str = "") -> str:
        return self.kv.get(table, {}).get(key, default)


def load_raw(raw_dir: str | Path) -> RawData:
    """Load every ``*.tsv`` fragment found in *raw_dir*."""
    raw_path = Path(raw_dir)
    data = RawData(raw_dir=raw_path)
    if not raw_path.is_dir():
        return data
    for path in sorted(raw_path.glob("*.tsv")):
        name = path.stem
        table = read_table(path)
        data.tables[name] = table
        # Only key/value fragments get dict views; wide tables (inventories)
        # would produce meaningless key collisions and waste memory.
        ncols = len(table[0]) if table else 0
        if 0 < ncols <= 2:
            data.kv[name] = read_kv(path)
            data.kv_multi[name] = kv_multi(path)
    return data


def write_csv(rows: list[dict[str, Any]], fieldnames: list[str], path: Path) -> int:
    """Write *rows* as CSV with *fieldnames*; returns the row count."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        count = 0
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})
            count += 1
    return count


def epoch_to_iso(epoch: str) -> str:
    """Convert a Unix epoch string to an ISO-8601 UTC timestamp."""
    try:
        from datetime import datetime, timezone

        seconds = int(float(epoch))
        if seconds <= 0:
            return ""
        return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except (ValueError, OverflowError, OSError):
        return ""


def human_bytes(num: float) -> str:
    """Format a byte count using binary units."""
    try:
        value = float(num)
    except (TypeError, ValueError):
        return str(num)
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    idx = 0
    while value >= 1024 and idx < len(units) - 1:
        value /= 1024
        idx += 1
    if idx == 0:
        return f"{int(value)} {units[idx]}"
    return f"{value:.1f} {units[idx]}"
