"""End-to-end tests for collector.report_processor (fragments -> reports)."""

from __future__ import annotations

import csv
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from collector.report_processor import DELIVERABLES, report_cli

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = PROJECT_ROOT / "config" / "config.template.json"


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def build_fixture_raw(raw: Path) -> None:
    """Create a small but representative set of TSV fragments."""
    raw.mkdir(parents=True, exist_ok=True)

    _write(raw / "detect.tsv",
           "key\tvalue\n"
           "hostname\tfixture-host\n"
           "distro_id\tubuntu\n")

    _write(raw / "system.general.tsv",
           "key\tvalue\n"
           "hostname\tfixture-host\n"
           "os\tUbuntu 24.04\n"
           "kernel\t6.8.0-generic\n"
           "arch\tx86_64\n")

    _write(raw / "system.cpu.tsv",
           "field\tvalue\n"
           "model\tTest CPU\n"
           "cores\t4\n")

    _write(raw / "system.memory.tsv",
           "type\ttotal_kb\tavailable_kb\tused_kb\ttotal_human\n"
           "memory\t16384000\t8192000\t8192000\t16GB\n"
           "swap\t0\t\t\t0B\n")

    _write(raw / "system.storage.tsv",
           "device\tsize\tmodel\ttransport\trotational\ttype\n"
           "/dev/sda\t500G\tTestDisk\tsata\t0\tnvme\n")

    _write(raw / "system.filesystems.tsv",
           "device\tmount\tfstype\tsize\tused\tavail\tuse_percent\n"
           "/dev/sda1\t/\text4\t100G\t50G\t50G\t50%\n")

    _write(raw / "filesystem.summary.tsv",
           "metric\tvalue\n"
           "files_scanned\t6\n"
           "directories_listed\t3\n"
           "total_bytes\t2048\n"
           "large_file_threshold_mb\t1\n"
           "large_file_count\t1\n"
           "contents_collected\tno\n")

    # Inventory: includes one LARGE file and one path with spaces.
    _write(raw / "filesystem.inventory.tsv",
           "category\tpath\tsize_bytes\tmtime_epoch\textension\tflags\n"
           "document\t/home/u/report.txt\t100\t1700000000\ttxt\t\n"
           "document\t/home/u/my report (2).txt\t200\t1700000001\ttxt\t\n"
           "image\t/home/u/pic.png\t300\t1700000002\tpng\t\n"
           "video\t/home/u/clip.mp4\t400\t1700000003\tmp4\t\n"
           "audio\t/home/u/song.mp3\t500\t1700000004\tmp3\t\n"
           "other\t/home/u/big.iso\t1572864\t1700000005\tiso\tLARGE\n")

    _write(raw / "media.summary.tsv",
           "metric\tvalue\n"
           "media_files\t5\n"
           "contents_collected\tno\n")

    _write(raw / "media.inventory.tsv",
           "category\tpath\tsize_bytes\tmtime_epoch\textension\tflags\n"
           "document\t/home/u/report.txt\t100\t1700000000\ttxt\t\n"
           "document\t/home/u/my report (2).txt\t200\t1700000001\ttxt\t\n"
           "image\t/home/u/pic.png\t300\t1700000002\tpng\t\n"
           "video\t/home/u/clip.mp4\t400\t1700000003\tmp4\t\n"
           "audio\t/home/u/song.mp3\t500\t1700000004\tmp3\t\n")

    _write(raw / "browser.installs.tsv",
           "browser\tinstalled\tbinary\tversion\tpackage_version\tsource\n"
           "firefox\tno\t\t\t\t\n"
           "chrome\tno\t\t\t\t\n")

    _write(raw / "browser.profiles.tsv",
           "browser\tprofile_name\tprofile_path\tprefs_file\n")

    _write(raw / "browser.not_accessed.tsv",
           "item\tstatus\n"
           "logins.json\tnot accessed\n"
           "Cookies\tnot accessed\n")

    _write(raw / "network.interfaces.tsv",
           "iface\tstate\tflags\tmtu\toperstate\n"
           "lo\tup\tloopback\t65536\tunknown\n"
           "eth0\tup\tBROADCAST,MULTICAST\t1500\tup\n")

    _write(raw / "network.addresses.tsv",
           "iface\tfamily\tscope\taddress\n"
           "eth0\tinet\tglobal\t192.168.1.10\n")

    _write(raw / "network.routes.tsv",
           "destination\tgateway\tdevice\tprotocol\n"
           "default\t192.168.1.1\teth0\tkernel\n")

    _write(raw / "network.dns.tsv", "source\tserver\n"
           "resolv.conf\t1.1.1.1\n")

    _write(raw / "network.connections.tsv",
           "protocol\tstate\tlocal_address\tpeer_address\tprocess\n"
           "tcp\tLISTEN\t0.0.0.0:22\t0.0.0.0:*\tsshd\n")

    _write(raw / "network.firewall.tsv",
           "backend\tstatus\tdetail\n"
           "ufw\tinactive\t\n")

    _write(raw / "network.adapters.tsv",
           "iface\tdriver\tversion\tfirmware\n"
           "eth0\te1000\t1.0\t\n")

    _write(raw / "network.exclusions.tsv", "item\tstatus\n")

    _write(raw / "software.managers.tsv",
           "manager\tavailable\tpath\n"
           "apt\tyes\t/usr/bin/apt\n")

    _write(raw / "software.packages.tsv",
           "manager\tname\tversion\n"
           "apt\topenssl\t3.0.13\n"
           "apt\tbash\t5.2.21\n")

    _write(raw / "software.services.tsv",
           "unit\tstate\n"
           "ssh.service\tenabled\n"
           "cron.service\trunning\n")

    _write(raw / "software.summary.tsv",
           "metric\tvalue\n"
           "package_count\t2\n"
           "services_total\t2\n")

    _write(raw / "tools.tsv",
           "command\tavailable\tpath\tfallback\n"
           "ip\tyes\t/usr/sbin/ip\t\n"
           "ss\tno\t\tnetstat\n")

    _write(raw / "skipped.tsv",
           "module\toperation\treason\n"
           "network\tss\tcommand not available: ss\n")

    _write(raw / "errors.tsv", "module\toperation\tmessage\n")


class TestReportCli(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.raw = base / "raw"
        self.out = base / "reports"
        self.out.mkdir()
        build_fixture_raw(self.raw)

    def _run(self, *extra: str) -> int:
        # The reporter prints a human summary; keep test output clean.
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return report_cli([
                "--raw", str(self.raw),
                "--out", str(self.out),
                "--config", str(TEMPLATE),
                "--scope", "/home/u",
                "--modules", "system,filesystem,media,browser,network,software",
                "--duration", "12",
                "--started-at", "2026-01-01T00:00:00Z",
                *extra,
            ])

    def test_all_deliverables_written(self) -> None:
        code = self._run()
        self.assertEqual(code, 0)
        for name in DELIVERABLES:
            with self.subTest(file=name):
                path = self.out / name
                self.assertTrue(path.is_file(), f"missing {name}")
                self.assertGreater(path.stat().st_size, 0)

    def test_json_structure(self) -> None:
        self.assertEqual(self._run(), 0)
        report = json.loads(
            (self.out / "system_report.json").read_text(encoding="utf-8")
        )

        info = report["report"]
        self.assertEqual(info["hostname"], "fixture-host")
        self.assertEqual(info["classification"], "CONFIDENTIAL")
        self.assertEqual(info["duration_seconds"], 12)
        self.assertEqual(info["scope"], ["/home/u"])
        self.assertEqual(len(info["modules_run"]), 6)

        fs = report["filesystem"]
        self.assertEqual(fs["inventory_total"], 6)
        self.assertEqual(fs["large_file_count"], 1)
        self.assertEqual(fs["large_files"][0]["path"], "/home/u/big.iso")
        self.assertEqual(fs["large_files"][0]["size_human"], "1.5 MiB")

        media = report["media"]
        self.assertEqual(media["total"], 5)
        self.assertEqual(
            media["counts"],
            {"document": 2, "image": 1, "video": 1, "audio": 1},
        )

        # Privacy contract is baked into every report.
        privacy = report["privacy"]
        self.assertIs(privacy["file_contents_collected"], False)
        self.assertIs(privacy["credentials_collected"], False)
        self.assertIs(privacy["packet_capture"], False)
        self.assertIs(privacy["persistence_installed"], False)
        self.assertIs(privacy["transmission_requires_approval"], True)
        self.assertTrue(privacy["notes"])

        self.assertEqual(report["collection"]["skipped_count"], 1)
        self.assertEqual(report["collection"]["errors_count"], 0)

    def test_html_and_txt_content(self) -> None:
        self.assertEqual(self._run(), 0)
        html = (self.out / "system_report.html").read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("fixture-host", html)
        self.assertIn("CONFIDENTIAL", html)

        txt = (self.out / "system_report.txt").read_text(encoding="utf-8")
        self.assertIn("fixture-host", txt)
        self.assertIn("metadata only", txt)
        self.assertIn("CONFIDENTIAL", txt)
        # TXT must stay plain ASCII for terminals/tickets.
        self.assertTrue(all(ord(ch) < 128 for ch in txt),
                        "TXT report contains non-ASCII characters")

    def test_csv_inventories(self) -> None:
        self.assertEqual(self._run(), 0)
        with (self.out / "filesystem_inventory.csv").open(
            encoding="utf-8", newline=""
        ) as fh:
            rows = list(csv.DictReader(fh))
        self.assertEqual(len(rows), 6)
        paths = [r["path"] for r in rows]
        self.assertIn("/home/u/my report (2).txt", paths)
        large = [r for r in rows if r["flags"] == "LARGE"]
        self.assertEqual(len(large), 1)
        self.assertEqual(large[0]["path"], "/home/u/big.iso")

        with (self.out / "media_inventory.csv").open(
            encoding="utf-8", newline=""
        ) as fh:
            media_rows = list(csv.DictReader(fh))
        self.assertEqual(len(media_rows), 5)

    def test_missing_raw_dir_still_writes_reports(self) -> None:
        empty = Path(self.tmp.name) / "empty-raw"
        empty.mkdir()
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = report_cli([
                "--raw", str(empty),
                "--out", str(self.out),
                "--config", str(TEMPLATE),
            ])
        self.assertEqual(code, 0)
        for name in DELIVERABLES:
            self.assertTrue((self.out / name).is_file())


if __name__ == "__main__":
    unittest.main()
