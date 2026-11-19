"""Command-line entry point: ``python -m collector <command>``.

Commands:
  config  — read/validate configuration (used by the Bash engine)
  report  — build HTML/JSON/TXT/CSV reports from raw fragments
  send    — preview or transmit approved report bundles over SMTP
"""

from __future__ import annotations

import sys

from . import TOOL_NAME, __version__


def main(argv: list[str] | None = None) -> int:
    # Windows text-mode stdout translates "\n" to CRLF when piped, which
    # would corrupt the TAB/line-delimited output the Bash engine parses.
    try:
        sys.stdout.reconfigure(newline="\n")
        sys.stderr.reconfigure(newline="\n")
    except (AttributeError, ValueError):  # pragma: no cover
        pass

    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(f"{TOOL_NAME} v{__version__}")
        print("usage: python -m collector {config|report|send|version} [options]")
        print("       python -m collector config --help")
        return 0

    command, rest = argv[0], argv[1:]

    if command in ("-V", "--version", "version"):
        print(f"{TOOL_NAME} collector-engine v{__version__}")
        return 0
    if command in ("-h", "--help", "help"):
        print(__doc__ or "")
        return 0
    if command == "config":
        from .config import config_cli

        return config_cli(rest)
    if command == "report":
        from .report_processor import report_cli

        return report_cli(rest)
    if command == "send":
        from .smtp_sender import send_cli

        return send_cli(rest)

    print(f"unknown command: {command}", file=sys.stderr)
    print("available commands: config, report, send, version", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
