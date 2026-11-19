"""Approved SMTP delivery of LFC reports.

Security rules enforced here:
  * Transmission is refused unless ``--approved`` is supplied (which the
    Bash engine only passes after an explicit interactive confirmation or
    an operator-provided ``--approve-send`` flag).
  * Credentials come only from environment variables named by the config
    (``username_env`` / ``password_env``). They are never logged, never
    written to disk and never embedded in the repository.
  * Attachment size is validated before any network connection is opened.
  * All failures are reported with distinct exit codes for the operator.
"""

from __future__ import annotations

import os
import smtplib
import socket
import ssl
import sys
import zipfile
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from .config import ConfigError, load_config, require_valid
from .report_processor import DELIVERABLES

EXIT_OK = 0
EXIT_NOT_APPROVED = 2
EXIT_CONFIG = 3
EXIT_TOO_LARGE = 4
EXIT_SMTP = 5

AUDIT_LOG_NAME = "audit.log"


def _log(message: str) -> None:
    print(f"[lfc-send] {message}", file=sys.stderr)


def append_audit(audit_log: Path | None, status: str, message: str) -> None:
    if audit_log is None:
        return
    try:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        line = f"{ts} | {status} | stage=delivery | module=smtp | user={_safe_user()} | {message}\n"
        with audit_log.open("a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass


def _safe_user() -> str:
    try:
        import getpass

        return getpass.getuser()
    except Exception:
        return "unknown"


def _read_hostname(reports_dir: Path) -> str:
    json_path = reports_dir / "system_report.json"
    try:
        import json

        data = json.loads(json_path.read_text(encoding="utf-8"))
        host = data.get("report", {}).get("hostname")
        if host:
            return str(host)
    except Exception:
        pass
    return socket.gethostname()


def build_bundle(
    reports_dir: Path, raw_dir: Path | None, cfg: dict[str, Any]
) -> tuple[list[tuple[str, bytes, str]], int]:
    """Return ([(filename, bytes, mime)], total_bytes) for the attachments."""
    files: list[tuple[str, bytes, str]] = []
    missing: list[str] = []
    for name in DELIVERABLES:
        path = reports_dir / name
        if path.is_file():
            files.append((name, path.read_bytes(), _mime_for(name)))
        else:
            missing.append(name)

    # The audit trail travels with the report so the recipient can verify
    # what was (and was not) collected during the run.
    audit = reports_dir / AUDIT_LOG_NAME
    if audit.is_file():
        files.append((AUDIT_LOG_NAME, audit.read_bytes(), "text/plain"))

    if missing:
        raise FileNotFoundError(
            "missing report file(s): " + ", ".join(sorted(missing))
        )

    attach_format = cfg["smtp"].get("attach_format", "zip")
    if attach_format == "zip":
        buf_name = f"lfc_report_{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.zip"
        from io import BytesIO

        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, data, _mime in files:
                zf.writestr(name, data)
        return [(buf_name, buffer.getvalue(), "application/zip")], buffer.tell()

    return files, sum(len(data) for _n, data, _m in files)


def _mime_for(name: str) -> str:
    if name.endswith(".html"):
        return "text/html"
    if name.endswith(".json"):
        return "application/json"
    if name.endswith(".csv"):
        return "text/csv"
    if name.endswith(".zip"):
        return "application/zip"
    return "text/plain"


def _compose_body(report: dict[str, Any] | None, hostname: str) -> str:
    lines = [
        "Linux Forensic Collector (LFC) — approved report delivery",
        "",
        f"Host: {hostname}",
        f"Sent: {datetime.now(tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} UTC",
        "",
        "This message contains forensic collection reports generated on the",
        "host above after explicit authorization by the machine owner.",
        "",
        "Privacy guarantees:",
        "  - No file contents were collected (metadata only).",
        "  - No passwords, cookies, tokens or private keys were accessed.",
        "  - No packet capture or credential capture was performed.",
        "",
        "Attachment(s) are listed in the message headers. Verify the SHA-256",
        "of received files against your local copies where applicable.",
        "",
        "Handle according to your organization's data classification policy.",
    ]
    if report:
        info = report.get("report", {})
        fs = report.get("filesystem", {})
        lines.insert(
            3,
            f"Files inventoried: {fs.get('inventory_total', 0)} | "
            f"Media: {report.get('media', {}).get('total', 0)} | "
            f"Errors: {report.get('collection', {}).get('errors_count', 0)} | "
            f"Skipped: {report.get('collection', {}).get('skipped_count', 0)}",
        )
        classification = info.get("classification", "")
        if classification:
            lines.insert(2, f"Classification: {classification}")
    return "\n".join(lines) + "\n"


def _load_report_dict(reports_dir: Path) -> dict[str, Any] | None:
    import json

    path = reports_dir / "system_report.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def send_reports(
    cfg: dict[str, Any],
    reports_dir: Path,
    approved: bool,
    preview: bool = False,
    raw_dir: Path | None = None,
    audit_log: Path | None = None,
) -> int:
    """Validate, (optionally) transmit the report bundle. Returns exit code."""
    if audit_log is None and reports_dir.is_dir():
        candidate = reports_dir / AUDIT_LOG_NAME
        audit_log = candidate if candidate.exists() else None

    if not approved and not preview:
        _log("REFUSED: transmission requires explicit approval")
        append_audit(audit_log, "DENY", "transmission refused: not approved")
        return EXIT_NOT_APPROVED

    smtp_cfg = cfg["smtp"]

    if not smtp_cfg.get("enabled"):
        if preview:
            print("SMTP delivery is disabled in the configuration (smtp.enabled=false).")
            return EXIT_OK
        _log("REFUSED: smtp.enabled is false")
        append_audit(audit_log, "DENY", "transmission refused: smtp disabled in config")
        return EXIT_CONFIG

    try:
        require_valid(cfg)
    except ConfigError as exc:
        _log(f"CONFIG ERROR: {exc}")
        append_audit(audit_log, "FAIL", f"config invalid: {exc}")
        return EXIT_CONFIG

    try:
        attachments, total_bytes = build_bundle(reports_dir, raw_dir, cfg)
    except FileNotFoundError as exc:
        _log(f"CONFIG/INPUT ERROR: {exc}")
        append_audit(audit_log, "FAIL", f"bundle incomplete: {exc}")
        return EXIT_CONFIG
    except OSError as exc:
        _log(f"ERROR reading reports: {exc}")
        append_audit(audit_log, "FAIL", f"bundle read error: {exc}")
        return EXIT_CONFIG

    max_bytes = int(smtp_cfg.get("max_attachment_mb", 20)) * 1024 * 1024
    hostname = _read_hostname(reports_dir)
    date_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
    subject = f"{smtp_cfg.get('subject_prefix', '[LFC]')} Forensic report for {hostname} ({date_str})"
    to_addrs = list(smtp_cfg.get("to_addr", []))
    from_addr = str(smtp_cfg.get("from_addr", ""))
    report = _load_report_dict(reports_dir)
    body = _compose_body(report, hostname)

    if preview:
        print("SMTP transmission plan (NOT sent):")
        print(f"  Host      : {smtp_cfg.get('host')}:{smtp_cfg.get('port')} "
              f"({smtp_cfg.get('tls_mode')})")
        print(f"  From      : {from_addr}")
        print(f"  To        : {', '.join(to_addrs)}")
        print(f"  Subject   : {subject}")
        print(f"  Auth env  : username=${smtp_cfg.get('username_env')} "
              f"password=${smtp_cfg.get('password_env')}")
        print(f"  Attachments ({len(attachments)}):")
        for name, data, mime in attachments:
            print(f"    - {name} ({len(data)} bytes, {mime})")
        print(f"  Total attachment bytes: {total_bytes} "
              f"(limit {max_bytes})")
        if total_bytes > max_bytes:
            print("  RESULT: would FAIL - attachment exceeds configured size limit")
            return EXIT_TOO_LARGE
        print("  RESULT: OK - re-run with --approved to transmit")
        return EXIT_OK

    if total_bytes > max_bytes:
        _log(
            f"REFUSED: attachment bundle is {total_bytes} bytes, "
            f"limit is {max_bytes} bytes (smtp.max_attachment_mb="
            f"{smtp_cfg.get('max_attachment_mb')})"
        )
        append_audit(
            audit_log,
            "FAIL",
            f"attachment too large: {total_bytes} > {max_bytes} bytes",
        )
        return EXIT_TOO_LARGE

    # --- credentials from environment only ---------------------------------
    user_env = str(smtp_cfg.get("username_env", "LFC_SMTP_USERNAME"))
    pass_env = str(smtp_cfg.get("password_env", "LFC_SMTP_PASSWORD"))
    username = os.environ.get(user_env, "")
    password = os.environ.get(pass_env, "")
    if username and not password:
        _log(f"CONFIG ERROR: {user_env} is set but {pass_env} is empty")
        append_audit(audit_log, "FAIL", f"missing credential env var: {pass_env}")
        return EXIT_CONFIG
    if password and not username:
        _log(f"CONFIG ERROR: {pass_env} is set but {user_env} is empty")
        append_audit(audit_log, "FAIL", f"missing credential env var: {user_env}")
        return EXIT_CONFIG

    # --- compose message ----------------------------------------------------
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    msg["Date"] = datetime.now(tz=timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    msg["X-LFC-Classification"] = str(cfg["meta"].get("report_classification", "CONFIDENTIAL"))
    msg.set_content(body)
    for name, data, mime in attachments:
        maintype, _, subtype = mime.partition("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)

    host = str(smtp_cfg["host"])
    port = int(smtp_cfg["port"])
    tls_mode = str(smtp_cfg["tls_mode"])
    timeout = int(smtp_cfg.get("timeout_seconds", 30))
    context = ssl.create_default_context()

    _log(f"Connecting to {host}:{port} ({tls_mode}) ...")
    append_audit(
        audit_log,
        "START",
        f"smtp send to {','.join(to_addrs)} via {host}:{port} ({tls_mode}), "
        f"bytes={total_bytes}",
    )

    server: smtplib.SMTP | None = None
    try:
        if tls_mode == "ssl":
            server = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
        else:
            server = smtplib.SMTP(host, port, timeout=timeout)
            server.ehlo()
            if tls_mode == "starttls":
                server.starttls(context=context)
                server.ehlo()
        if username:
            server.login(username, password)
        server.send_message(msg)
        _log("Delivered successfully.")
        append_audit(audit_log, "OK", f"reports delivered to {','.join(to_addrs)}")
        return EXIT_OK
    except smtplib.SMTPAuthenticationError as exc:
        _log(f"SMTP AUTH FAILED: {exc} (check {user_env}/{pass_env})")
        append_audit(audit_log, "FAIL", f"smtp auth failed: {exc}")
        return EXIT_SMTP
    except smtplib.SMTPRecipientsRefused as exc:
        _log(f"RECIPIENT REFUSED: {exc}")
        append_audit(audit_log, "FAIL", f"recipients refused: {exc}")
        return EXIT_SMTP
    except smtplib.SMTPException as exc:
        _log(f"SMTP ERROR: {type(exc).__name__}: {exc}")
        append_audit(audit_log, "FAIL", f"smtp error: {type(exc).__name__}: {exc}")
        return EXIT_SMTP
    except (socket.timeout, TimeoutError) as exc:
        _log(f"CONNECTION TIMEOUT: {exc}")
        append_audit(audit_log, "FAIL", f"smtp timeout: {exc}")
        return EXIT_SMTP
    except (OSError, ssl.SSLError) as exc:
        _log(f"CONNECTION ERROR: {type(exc).__name__}: {exc}")
        append_audit(audit_log, "FAIL", f"smtp connection error: {exc}")
        return EXIT_SMTP
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                try:
                    server.close()
                except Exception:
                    pass


def send_cli(argv: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="lfc send", description="Deliver approved LFC reports over SMTP"
    )
    parser.add_argument("--config", required=True, help="JSON config file")
    parser.add_argument("--reports", required=True, help="report directory")
    parser.add_argument("--raw", default=None, help="raw fragment directory")
    parser.add_argument("--approved", action="store_true",
                        help="operator approved transmission")
    parser.add_argument("--preview", action="store_true",
                        help="show the transmission plan without sending")
    args = parser.parse_args(argv)

    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        _log(f"CONFIG ERROR: {exc}")
        return EXIT_CONFIG

    reports_dir = Path(args.reports)
    raw_dir = Path(args.raw) if args.raw else None
    return send_reports(
        cfg,
        reports_dir,
        approved=args.approved,
        preview=args.preview,
        raw_dir=raw_dir,
    )
