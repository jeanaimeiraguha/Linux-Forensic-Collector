"""Unit tests for collector.config (validation, defaults, CLI)."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from collector.config import (
    DEFAULTS,
    ConfigError,
    config_cli,
    get_dotted,
    load_config,
    require_valid,
    validate,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = PROJECT_ROOT / "config" / "config.template.json"


class TestLoadConfig(unittest.TestCase):
    def test_defaults_without_file(self) -> None:
        import os

        cfg = load_config(None)
        # $HOME in scope_paths is expanded at load time (may be a no-op
        # when the variable is unset), everything else stays as declared.
        self.assertEqual(
            cfg["collection"]["scope_paths"],
            [os.path.expandvars("$HOME")],
        )
        stripped_cfg = json.loads(json.dumps(cfg))
        stripped_defaults = json.loads(json.dumps(DEFAULTS))
        stripped_cfg["collection"].pop("scope_paths", None)
        stripped_defaults["collection"].pop("scope_paths", None)
        self.assertEqual(stripped_cfg, stripped_defaults)
        self.assertIs(cfg["smtp"]["enabled"], False)
        self.assertEqual(
            cfg["collection"]["modules"]["filesystem"], True
        )

    def test_template_is_valid(self) -> None:
        self.assertTrue(TEMPLATE.is_file(), f"missing {TEMPLATE}")
        cfg = load_config(TEMPLATE)
        errors = validate(cfg)
        self.assertEqual(errors, [])

    def test_template_recipient_is_project_address(self) -> None:
        cfg = load_config(TEMPLATE)
        self.assertEqual(
            cfg["smtp"]["to_addr"], ["jeanaiameiraguha@gmail.com"]
        )
        # Credentials must never live in the config file: only the NAMES of
        # the environment variables that hold them.
        self.assertEqual(
            cfg["smtp"]["username_env"], "LFC_SMTP_USERNAME"
        )
        self.assertEqual(
            cfg["smtp"]["password_env"], "LFC_SMTP_PASSWORD"
        )
        # No literal credential keys anywhere in the effective config.
        def _keys(node, prefix=""):
            if isinstance(node, dict):
                for key, val in node.items():
                    yield f"{prefix}.{key}" if prefix else key
                    yield from _keys(val, f"{prefix}.{key}" if prefix else key)
        self.assertNotIn("password", list(_keys(cfg)))

    def test_missing_file_raises(self) -> None:
        with self.assertRaises(ConfigError):
            load_config("/nonexistent/lfc.json")

    def test_invalid_json_raises(self) -> None:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False
        ) as fh:
            fh.write("{not json")
            path = fh.name
        try:
            with self.assertRaises(ConfigError) as ctx:
                load_config(path)
            self.assertIn("invalid JSON", str(ctx.exception))
        finally:
            Path(path).unlink()

    def test_non_object_root_raises(self) -> None:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False
        ) as fh:
            json.dump([1, 2], fh)
            path = fh.name
        try:
            with self.assertRaises(ConfigError):
                load_config(path)
        finally:
            Path(path).unlink()

    def test_override_merges_one_layer(self) -> None:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False
        ) as fh:
            json.dump({"smtp": {"enabled": True, "host": "mail.example"}},
                      fh)
            path = fh.name
        try:
            cfg = load_config(path)
            self.assertIs(cfg["smtp"]["enabled"], True)
            self.assertEqual(cfg["smtp"]["host"], "mail.example")
            # Untouched keys survive the merge.
            self.assertEqual(cfg["smtp"]["port"], 587)
        finally:
            Path(path).unlink()

    def test_home_expansion(self) -> None:
        import os
        from unittest import mock

        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False
        ) as fh:
            json.dump({"collection": {"scope_paths": ["$HOME/data"]}}, fh)
            path = fh.name
        try:
            with mock.patch.dict(os.environ, {"HOME": "/home/tester"}):
                cfg = load_config(path)
            self.assertEqual(
                cfg["collection"]["scope_paths"], ["/home/tester/data"]
            )
        finally:
            Path(path).unlink()


class TestValidate(unittest.TestCase):
    def _cfg(self, **patch) -> dict:
        cfg = json.loads(json.dumps(DEFAULTS))
        for section, values in patch.items():
            cfg.setdefault(section, {}).update(values)
        return cfg

    def test_defaults_valid(self) -> None:
        self.assertEqual(validate(DEFAULTS), [])

    def test_bad_email(self) -> None:
        cfg = self._cfg(smtp={"to_addr": ["not-an-email"]})
        self.assertTrue(any("invalid address" in e for e in validate(cfg)))

    def test_enabled_requires_host_from_and_recipients(self) -> None:
        cfg = self._cfg(smtp={"enabled": True, "to_addr": []})
        errs = validate(cfg)
        self.assertTrue(any("smtp.host" in e for e in errs))
        self.assertTrue(any("smtp.to_addr" in e for e in errs))
        self.assertTrue(any("smtp.from_addr" in e for e in errs))

    def test_unknown_module_rejected(self) -> None:
        cfg = self._cfg(collection={"modules": {"crypto-miner": True}})
        self.assertTrue(
            any("unknown module" in e for e in validate(cfg))
        )

    def test_module_must_be_bool(self) -> None:
        cfg = self._cfg(collection={"modules": {"system": "yes"}})
        self.assertTrue(
            any("must be true/false" in e for e in validate(cfg))
        )

    def test_max_depth_bounds(self) -> None:
        cfg = self._cfg(collection={"max_depth": 0})
        self.assertTrue(any("max_depth" in e for e in validate(cfg)))

    def test_port_bounds(self) -> None:
        cfg = self._cfg(smtp={"port": 70000})
        self.assertTrue(any("smtp.port" in e for e in validate(cfg)))

    def test_tls_mode_enum(self) -> None:
        cfg = self._cfg(smtp={"tls_mode": "carrier-pigeon"})
        self.assertTrue(any("tls_mode" in e for e in validate(cfg)))

    def test_scope_paths_must_be_strings(self) -> None:
        cfg = self._cfg(collection={"scope_paths": [1, 2]})
        self.assertTrue(
            any("scope_paths" in e for e in validate(cfg))
        )

    def test_require_valid_raises(self) -> None:
        cfg = self._cfg(smtp={"to_addr": ["bad"]})
        with self.assertRaises(ConfigError):
            require_valid(cfg)


class TestConfigCli(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "cfg.json"
        self.path.write_text(json.dumps(DEFAULTS), encoding="utf-8")

    def _run(self, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = config_cli(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_validate_ok(self) -> None:
        code, out, _ = self._run("--config", str(self.path), "--validate")
        self.assertEqual(code, 0)
        self.assertIn("configuration OK", out)

    def test_validate_bad_config_exits_3(self) -> None:
        bad = Path(self.tmp.name) / "bad.json"
        bad.write_text(
            json.dumps({"smtp": {"to_addr": ["nope"]}}), encoding="utf-8"
        )
        code, _, err = self._run("--config", str(bad), "--validate")
        self.assertEqual(code, 3)
        self.assertIn("invalid", err)

    def test_get_dotted(self) -> None:
        code, out, _ = self._run(
            "--config", str(self.path), "--get", "smtp.port"
        )
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "587")

    def test_get_bool_stringified(self) -> None:
        code, out, _ = self._run(
            "--config", str(self.path), "--get", "smtp.enabled"
        )
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "false")

    def test_get_unknown_key_exits_3(self) -> None:
        code, _, err = self._run(
            "--config", str(self.path), "--get", "no.such.key"
        )
        self.assertEqual(code, 3)
        self.assertIn("unknown config key", err)

    def test_get_array(self) -> None:
        code, out, _ = self._run(
            "--config", str(TEMPLATE), "--get-array", "smtp.to_addr"
        )
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "jeanaiameiraguha@gmail.com")

    def test_flatten_has_expected_keys(self) -> None:
        code, out, _ = self._run(
            "--config", str(self.path), "--flatten"
        )
        self.assertEqual(code, 0)
        keys = {line.split("\t", 1)[0] for line in out.splitlines()}
        for expected in (
            "smtp.host",
            "smtp.to_addr",
            "collection.max_depth",
            "collection.modules.system",
            "meta.report_classification",
        ):
            self.assertIn(expected, keys)

    def test_get_dotted_helper(self) -> None:
        cfg = {"a": {"b": {"c": 5}}}
        self.assertEqual(get_dotted(cfg, "a.b.c"), 5)
        with self.assertRaises(KeyError):
            get_dotted(cfg, "a.x")


if __name__ == "__main__":
    unittest.main()
