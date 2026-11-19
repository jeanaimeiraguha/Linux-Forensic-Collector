"""Unit tests for collector.browser_prefs (allowlist + parsers).

The docstring of browser_prefs.py promises that the allowlist is asserted
against the denylist regex here, so any future allowlist addition that looks
like a credential/secret must fail this suite and be reviewed deliberately.
"""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from collector.browser_prefs import (
    ALLOWED_PREF_KEYS,
    DENYLIST_RE,
    MAX_VALUE_LENGTH,
    inspect_profiles,
    key_allowed,
    parse_chrome_prefs,
    parse_firefox_prefs,
)


class TestAllowlistPolicy(unittest.TestCase):
    def test_allowlisted_keys_pass(self) -> None:
        for key in ALLOWED_PREF_KEYS:
            with self.subTest(key=key):
                self.assertTrue(key_allowed(key))

    def test_prefixed_allowlisted_keys_pass(self) -> None:
        self.assertTrue(
            key_allowed("browser.safebrowsing.enabled")
        )
        self.assertTrue(
            key_allowed("privacy.privacy.donottrackheader.enabled")
        )

    def test_non_allowlisted_keys_fail(self) -> None:
        for key in (
            "homepage",
            "browser.startup.homepage",
            "signon.rememberSignons",
            "network.cookie.cookieBehavior",
            "extensions.webextensions.uuids",
        ):
            with self.subTest(key=key):
                self.assertFalse(key_allowed(key))

    def test_no_allowlisted_key_matches_denylist(self) -> None:
        """The security promise: nothing credential-like is allowlisted."""
        for key in ALLOWED_PREF_KEYS:
            with self.subTest(key=key):
                self.assertIsNone(
                    DENYLIST_RE.search(key),
                    f"allowlisted key {key!r} looks like a secret",
                )

    def test_denylist_covers_sensitive_names(self) -> None:
        for key in (
            "browser.passwords.enabled",
            "auth_token",
            "session_cookie",
            "api_key",
            "private_key",
            "credentials.store",
        ):
            with self.subTest(key=key):
                self.assertTrue(DENYLIST_RE.search(key))

    def test_denylisted_path_never_allowed(self) -> None:
        # Even if a future allowlist entry collides with the denylist,
        # key_allowed must refuse it.
        fake_allowed = "password.safebrowsing.enabled"
        self.assertFalse(key_allowed(fake_allowed))


class TestChromePrefs(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_extracts_only_allowlisted(self) -> None:
        path = self.dir / "Preferences"
        path.write_text(
            json.dumps(
                {
                    "safebrowsing": {
                        "enabled": True,
                        "malware": {"enabled": False},
                    },
                    "network": {"dns": {"disablePrefetch": True}},
                    "credentials": {"password": "hunter2"},
                    "homepage": "https://example.com",
                    "session": {"token": "abc"},
                }
            ),
            encoding="utf-8",
        )
        prefs = parse_chrome_prefs(path)
        self.assertIs(prefs.get("safebrowsing.enabled"), True)
        self.assertIs(prefs.get("safebrowsing.malware.enabled"), False)
        self.assertIs(prefs.get("network.dns.disablePrefetch"), True)
        # Nothing sensitive or unrelated leaks through.
        blob = json.dumps(prefs)
        self.assertNotIn("hunter2", blob)
        self.assertNotIn("homepage", blob)
        self.assertNotIn("token", blob)

    def test_invalid_json_returns_empty(self) -> None:
        path = self.dir / "Preferences"
        path.write_text("{broken", encoding="utf-8")
        self.assertEqual(parse_chrome_prefs(path), {})

    def test_long_values_dropped(self) -> None:
        path = self.dir / "Preferences"
        # search.suggest.enabled allowlisted, but give a huge string value
        # under an allowlisted leaf to prove MAX_VALUE_LENGTH applies.
        long_str = "x" * (MAX_VALUE_LENGTH + 1)
        path.write_text(
            json.dumps(
                {
                    "search": {
                        "suggest": {"enabled": long_str},
                    }
                }
            ),
            encoding="utf-8",
        )
        prefs = parse_chrome_prefs(path)
        self.assertEqual(prefs, {})


class TestFirefoxFPrefs(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_parses_user_prefs(self) -> None:
        path = self.dir / "prefs.js"
        path.write_text(
            '// comment\n'
            'user_pref("privacy.donottrackheader.enabled", true);\n'
            'user_pref("security.tls.version.min", 3);\n'
            'user_pref("browser.safebrowsing.enabled", false);\n'
            'user_pref("signon.rememberSignons", false);\n'
            'user_pref("network.http.referer.XOriginTrimmingPolicy", 2);\n',
            encoding="utf-8",
        )
        prefs = parse_firefox_prefs(path)
        self.assertIs(prefs.get("privacy.donottrackheader.enabled"), True)
        self.assertEqual(prefs.get("security.tls.version.min"), 3)
        self.assertIs(prefs.get("browser.safebrowsing.enabled"), False)
        self.assertNotIn("signon.rememberSignons", prefs)
        self.assertNotIn(
            "network.http.referer.XOriginTrimmingPolicy", prefs
        )

    def test_missing_file_returns_empty(self) -> None:
        self.assertEqual(
            parse_firefox_prefs(self.dir / "prefs.js"), {}
        )


class TestInspectProfiles(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_skips_rows_without_prefs_file(self) -> None:
        rows = [
            {"browser": "firefox", "profile_name": "default",
             "profile_path": "/x", "prefs_file": ""},
            {"browser": "chrome", "profile_name": "p1",
             "profile_path": "/y", "prefs_file": str(self.dir / "gone")},
        ]
        self.assertEqual(inspect_profiles(rows), {})

    def test_parses_valid_profile(self) -> None:
        prefs_file = self.dir / "prefs.js"
        prefs_file.write_text(
            'user_pref("browser.safebrowsing.enabled", true);\n',
            encoding="utf-8",
        )
        rows = [
            {"browser": "firefox", "profile_name": "default-release",
             "profile_path": str(self.dir),
             "prefs_file": str(prefs_file)},
        ]
        result = inspect_profiles(rows)
        self.assertIn("firefox", result)
        self.assertIn("default-release", result["firefox"])
        self.assertEqual(
            result["firefox"]["default-release"]["prefs"].get(
                "browser.safebrowsing.enabled"
            ),
            True,
        )
        # The prefs path itself is the only filesystem detail retained.
        self.assertEqual(
            result["firefox"]["default-release"]["prefs_path"],
            str(prefs_file),
        )

    def test_renamed_prefs_file_skipped(self) -> None:
        weird = self.dir / "backups-prefs.js"
        weird.write_text(
            'user_pref("browser.safebrowsing.enabled", true);\n',
            encoding="utf-8",
        )
        rows = [
            {"browser": "firefox", "profile_name": "p",
             "profile_path": str(self.dir), "prefs_file": str(weird)},
        ]
        self.assertEqual(inspect_profiles(rows), {})


class TestDenylistRegex(unittest.TestCase):
    def test_denylist_is_case_insensitive(self) -> None:
        self.assertTrue(DENYLIST_RE.search("Browser.Passwords.Enabled"))

    def test_denylist_word_boundaries(self) -> None:
        # "credential" style words anywhere in the dotted path.
        self.assertTrue(DENYLIST_RE.search("account.credentials.vault"))


if __name__ == "__main__":
    unittest.main()
