"""Allowlisted browser security-preference inspection for LFC.

STRICT PRIVACY CONTRACT
-----------------------
This module reads browser preference files *only* to extract a small,
explicitly allowlisted set of non-sensitive security posture indicators.
It never touches password stores (logins.json, Login Data), cookies,
session tokens, private keys, autofill data, history or account material.

Allowlist policy
----------------
* A preference is reported only if its dotted path equals an allowlisted
  entry or ends with ``.<entry>`` (to accommodate browser key prefixes
  such as ``browser.safebrowsing.enabled``).
* The allowlist is asserted against a denylist regex in the test suite
  (tests/python/test_browser_prefs.py), so any future addition that looks
  like a credential/secret must be reviewed deliberately.
* Values are restricted to booleans, numbers and short strings.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# Non-sensitive security posture indicators only.
ALLOWED_PREF_KEYS: tuple[str, ...] = (
    "safebrowsing.enabled",
    "safebrowsing.malware.enabled",
    "safebrowsing.phishing.enabled",
    "safebrowsing.extended_reporting.enabled",
    "safebrowsing.downloads.enabled",
    "do_not_track",
    "enable_do_not_track",
    "privacy.donottrackheader.enabled",
    "ssl.enable_ocsp_stapling",
    "network.dns.disablePrefetch",
    "security.tls.version.min",
    "security.insecure_connection_warning.enabled",
    "browser.urlbar.suggest.searches",
    "search.suggest.enabled",
)

# Belt-and-braces: values or keys that must never be emitted even if a
# future allowlist entry were added carelessly.
DENYLIST_RE = re.compile(
    r"password|passwd|cookie|token|secret|credential|private[_-]?key|"
    r"api[_-]?key|session|autofill|payment|recovery[_-]?email",
    re.IGNORECASE,
)

MAX_VALUE_LENGTH = 64


def key_allowed(dotted_path: str) -> bool:
    """True when *dotted_path* matches the allowlist (exact or suffix)."""
    if DENYLIST_RE.search(dotted_path):
        # A denylisted path can never be reported, even if allowlisted.
        return False
    for entry in ALLOWED_PREF_KEYS:
        if dotted_path == entry or dotted_path.endswith("." + entry):
            return True
    return False


def _clean_value(value: Any) -> Any | None:
    """Keep only low-risk value types; return None to drop the value."""
    if isinstance(value, bool) or isinstance(value, int) or isinstance(value, float):
        return value
    if isinstance(value, str):
        if len(value) > MAX_VALUE_LENGTH:
            return None
        if DENYLIST_RE.search(value):
            return None
        return value
    return None


def _walk(node: Any, prefix: str, out: dict[str, Any]) -> None:
    if isinstance(node, dict):
        for key, val in node.items():
            if not isinstance(key, str):
                continue
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(val, (dict, list)):
                _walk(val, path, out)
            elif key_allowed(path):
                cleaned = _clean_value(val)
                if cleaned is not None:
                    out[path] = cleaned
    elif isinstance(node, list):
        for idx, val in enumerate(node):
            if isinstance(val, (dict, list)):
                _walk(val, f"{prefix}[{idx}]", out)


def parse_chrome_prefs(path: Path) -> dict[str, Any]:
    """Parse a Chromium ``Preferences`` JSON file (allowlisted keys only)."""
    out: dict[str, Any] = {}
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError, ValueError):
        return out
    if isinstance(data, dict):
        _walk(data, "", out)
    return out


_FIREFOX_PREF_RE = re.compile(
    r'^\s*user_pref\(\s*"([^"]+)"\s*,\s*(.+?)\s*\)\s*;?\s*$'
)


def _parse_firefox_value(raw: str) -> Any | None:
    raw = raw.strip()
    if raw == "true":
        return True
    if raw == "false":
        return False
    if re.fullmatch(r"-?\d+", raw):
        try:
            return int(raw)
        except ValueError:
            return None
    if re.fullmatch(r"-?\d+\.\d+", raw):
        try:
            return float(raw)
        except ValueError:
            return None
    if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return raw[1:-1]
    return None


def parse_firefox_prefs(path: Path) -> dict[str, Any]:
    """Parse Firefox ``prefs.js`` (allowlisted ``user_pref`` keys only)."""
    out: dict[str, Any] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        match = _FIREFOX_PREF_RE.match(line)
        if not match:
            continue
        key, raw_value = match.group(1), match.group(2)
        if not key_allowed(key):
            continue
        cleaned = _clean_value(_parse_firefox_value(raw_value))
        if cleaned is not None:
            out[key] = cleaned
    return out


def inspect_profiles(profile_rows: list[dict[str, str]]) -> dict[str, Any]:
    """Inspect every profile listed by the browser module.

    Returns a structure safe to embed in reports:
    ``{browser: {profile: {prefs_path, prefs: {...}}}}``.
    """
    result: dict[str, Any] = {}
    for row in profile_rows:
        browser = row.get("browser", "")
        profile = row.get("profile_name", "")
        prefs_file = row.get("prefs_file", "")
        if not browser or not prefs_file:
            continue
        path = Path(prefs_file)
        if not path.is_file():
            continue
        if path.name == "prefs.js":
            prefs = parse_firefox_prefs(path)
        elif path.name == "Preferences":
            prefs = parse_chrome_prefs(path)
        else:
            continue
        if not prefs:
            continue
        result.setdefault(browser, {})[profile] = {
            "prefs_path": str(path),
            "prefs": prefs,
        }
    return result
