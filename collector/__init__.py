"""Linux Forensic Collector (LFC) — Python reporting and delivery package.

This package NEVER collects data by itself; it only processes fragments
produced by the Bash collection engine, validates configuration, builds
reports and (after explicit approval) transmits them over SMTP.
"""

__version__ = "1.0.0"
TOOL_NAME = "Linux Forensic Collector (LFC)"
