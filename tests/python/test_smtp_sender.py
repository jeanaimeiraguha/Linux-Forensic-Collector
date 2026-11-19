"""Tests for collector.smtp_sender (approval gate, size gate, SMTP mock)."""

from __future__ import annotations

import io
import json
import os
import smtplib
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from collector.config import load_config
from collector.report_processor import DELIVERABLES
from collector.smtp_sender import (
    EXIT_CONFIG,
    EXIT_NOT_APPROVED,
    EXIT_OK,
    EXIT_SMTP,
    EXIT_TOO_LARGE,
    build_bundle,
    send_reports,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = PROJECT_ROOT / "config" / "config.template.json"


def make_reports(base: Path, pad_bytes: int = 0) -> Path:
    """Create a report directory containing all deliverables."""
    reports = base / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    for name in DELIVERABLES:
        content = f"fixture content for {name}\n"
        (reports / name).write_text(content, encoding="utf-8")
    (reports / "audit.log").write_text(
        "2026-01-01T00:00:00Z | START | stage=collect | module=main | "
        "user=test | run begin\n",
        encoding="utf-8",
    )
    (reports / "system_report.json").write_text(
        json.dumps({"report": {"hostname": "fixture-host"}}),
        encoding="utf-8",
    )
    if pad_bytes:
        # Random bytes do not compress, so the ZIP bundle really grows.
        with (reports / "system_report.txt").open("ab") as fh:
            fh.write(os.urandom(pad_bytes))
    return reports


def enabled_smtp_config() -> dict:
    cfg = load_config(TEMPLATE)
    cfg["smtp"].update(
        {
            "enabled": True,
            "host": "smtp.example.test",
            "port": 587,
            "tls_mode": "starttls",
            "from_addr": "lfc@example.test",
            "to_addr": ["jeanaiameiraguha@gmail.com"],
            "max_attachment_mb": 20,
        }
    )
    return cfg


class TestApprovalGate(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.reports = make_reports(self.base)
        self.cfg = enabled_smtp_config()

    def test_without_approval_returns_2(self) -> None:
        code = send_reports(self.cfg, self.reports, approved=False)
        self.assertEqual(code, EXIT_NOT_APPROVED)

    def test_denial_recorded_in_audit_log(self) -> None:
        send_reports(self.cfg, self.reports, approved=False)
        audit = (self.reports / "audit.log").read_text(encoding="utf-8")
        self.assertIn("DENY", audit)
        self.assertIn("not approved", audit)

    def test_smtp_disabled_and_not_preview_returns_3(self) -> None:
        cfg = load_config(TEMPLATE)  # smtp.enabled defaults to false
        code = send_reports(cfg, self.reports, approved=True)
        self.assertEqual(code, EXIT_CONFIG)

    def test_smtp_disabled_preview_returns_0(self) -> None:
        cfg = load_config(TEMPLATE)
        out = io.StringIO()
        with redirect_stdout(out):
            code = send_reports(
                cfg, self.reports, approved=True, preview=True
            )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("disabled", out.getvalue())


class TestBundle(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.reports = make_reports(self.base)
        self.cfg = enabled_smtp_config()

    def test_zip_bundle_contains_all_deliverables(self) -> None:
        import zipfile
        from io import BytesIO

        attachments, total = build_bundle(self.reports, None, self.cfg)
        self.assertEqual(len(attachments), 1)
        name, data, mime = attachments[0]
        self.assertTrue(name.startswith("lfc_report_"))
        self.assertTrue(name.endswith(".zip"))
        self.assertEqual(mime, "application/zip")
        self.assertEqual(total, len(data))

        with zipfile.ZipFile(BytesIO(data)) as zf:
            names = set(zf.namelist())
        for expected in list(DELIVERABLES) + ["audit.log"]:
            self.assertIn(expected, names)

    def test_missing_deliverable_raises(self) -> None:
        (self.reports / "system_report.html").unlink()
        with self.assertRaises(FileNotFoundError):
            build_bundle(self.reports, None, self.cfg)


class TestSizeGate(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.cfg = enabled_smtp_config()
        # Limit the bundle to 1 MiB.
        self.cfg["smtp"]["max_attachment_mb"] = 1

    def test_oversized_preview_returns_4(self) -> None:
        reports = make_reports(self.base, pad_bytes=2 * 1024 * 1024)
        out = io.StringIO()
        with redirect_stdout(out):
            code = send_reports(
                self.cfg, reports, approved=True, preview=True
            )
        self.assertEqual(code, EXIT_TOO_LARGE)
        self.assertIn("exceeds configured size limit", out.getvalue())

    def test_oversized_send_returns_4_without_connecting(self) -> None:
        reports = make_reports(self.base, pad_bytes=2 * 1024 * 1024)
        with mock.patch.object(smtplib, "SMTP") as smtp_cls:
            code = send_reports(self.cfg, reports, approved=True)
        self.assertEqual(code, EXIT_TOO_LARGE)
        smtp_cls.assert_not_called()


class TestCredentialEnv(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.reports = make_reports(self.base)
        self.cfg = enabled_smtp_config()
        self.env_patcher = mock.patch.dict(
            os.environ, {}, clear=False
        )
        self.env_patcher.start()
        self.addCleanup(self.env_patcher.stop)
        for var in ("LFC_SMTP_USERNAME", "LFC_SMTP_PASSWORD"):
            os.environ.pop(var, None)

    def test_no_credentials_means_unauthenticated_connection(self) -> None:
        # With neither env var set the sender may still use an unauthenticated
        # relay (common for local/lab SMTP); it must never invent credentials.
        with mock.patch.object(smtplib, "SMTP") as smtp_cls:
            code = send_reports(self.cfg, self.reports, approved=True)
        self.assertEqual(code, EXIT_OK)
        smtp_cls.return_value.login.assert_not_called()
        smtp_cls.return_value.send_message.assert_called_once()

    def test_half_configured_credentials_returns_3(self) -> None:
        os.environ["LFC_SMTP_USERNAME"] = "user@example.test"
        with mock.patch.object(smtplib, "SMTP") as smtp_cls:
            code = send_reports(self.cfg, self.reports, approved=True)
        self.assertEqual(code, EXIT_CONFIG)
        smtp_cls.assert_not_called()


class TestSmtpSendMocked(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.reports = make_reports(self.base)
        self.cfg = enabled_smtp_config()

    def test_successful_transmission(self) -> None:
        env = {
            "LFC_SMTP_USERNAME": "user@example.test",
            "LFC_SMTP_PASSWORD": "not-a-real-password",
        }
        with mock.patch.dict(os.environ, env, clear=False), \
                mock.patch.object(smtplib, "SMTP") as smtp_cls:
            server = smtp_cls.return_value
            code = send_reports(self.cfg, self.reports, approved=True)

        self.assertEqual(code, EXIT_OK)
        smtp_cls.assert_called_once_with(
            "smtp.example.test", 587, timeout=30
        )
        server.ehlo.assert_called()
        server.starttls.assert_called()
        server.login.assert_called_once_with(
            "user@example.test", "not-a-real-password"
        )
        server.send_message.assert_called_once()
        server.quit.assert_called()

        # Audit trail records success.
        audit = (self.reports / "audit.log").read_text(encoding="utf-8")
        self.assertIn("OK", audit)
        self.assertIn("delivered", audit)

    def test_subject_and_recipients(self) -> None:
        env = {
            "LFC_SMTP_USERNAME": "user@example.test",
            "LFC_SMTP_PASSWORD": "pw",
        }
        with mock.patch.dict(os.environ, env, clear=False), \
                mock.patch.object(smtplib, "SMTP") as smtp_cls:
            send_reports(self.cfg, self.reports, approved=True)

        msg = smtp_cls.return_value.send_message.call_args[0][0]
        self.assertEqual(
            msg["To"], "jeanaiameiraguha@gmail.com"
        )
        self.assertTrue(msg["Subject"].startswith("[LFC]"))
        self.assertIn("fixture-host", msg["Subject"])

    def test_smtp_failure_returns_5(self) -> None:
        env = {
            "LFC_SMTP_USERNAME": "user@example.test",
            "LFC_SMTP_PASSWORD": "pw",
        }
        with mock.patch.dict(os.environ, env, clear=False), \
                mock.patch.object(smtplib, "SMTP") as smtp_cls:
            smtp_cls.return_value.send_message.side_effect = (
                smtplib.SMTPException("boom")
            )
            code = send_reports(self.cfg, self.reports, approved=True)
        self.assertEqual(code, EXIT_SMTP)


if __name__ == "__main__":
    unittest.main()
