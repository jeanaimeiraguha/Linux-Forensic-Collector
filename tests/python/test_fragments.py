"""Unit tests for collector.fragments (TSV escape/unescape round trip)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from collector.fragments import (
    epoch_to_iso,
    human_bytes,
    kv_multi,
    load_raw,
    read_kv,
    read_table,
    unescape,
    write_csv,
)


class TestUnescape(unittest.TestCase):
    def test_roundtrip_tab_newline_cr_backslash(self) -> None:
        original = "a\tb\nc\rd\\e"
        escaped = (
            original.replace("\\", "\\\\")
            .replace("\t", "\\t")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
        )
        self.assertEqual(unescape(escaped), original)

    def test_plain_string_unchanged(self) -> None:
        self.assertEqual(unescape("/home/user/file.txt"), "/home/user/file.txt")

    def test_unknown_escape_preserved(self) -> None:
        # Unknown sequences must survive as literal text.
        self.assertEqual(unescape("a\\zb"), "a\\zb")

    def test_trailing_backslash(self) -> None:
        self.assertEqual(unescape("end\\"), "end\\")


class TestReadTable(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_reads_header_and_rows(self) -> None:
        p = self.dir / "t.tsv"
        p.write_text(
            "category\tpath\tsize_bytes\n"
            "document\t/a/b.txt\t12\n"
            "image\t/c\\td.png\t34\n",
            encoding="utf-8",
        )
        rows = read_table(p)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["category"], "document")
        self.assertEqual(rows[0]["size_bytes"], "12")
        # Escaped tab inside a path is restored.
        self.assertEqual(rows[1]["path"], "/c\td.png")

    def test_short_rows_padded(self) -> None:
        p = self.dir / "short.tsv"
        p.write_text("a\tb\tc\nonly-one\n", encoding="utf-8")
        rows = read_table(p)
        self.assertEqual(rows, [{"a": "only-one", "b": "", "c": ""}])

    def test_missing_file_returns_empty(self) -> None:
        self.assertEqual(read_table(self.dir / "nope.tsv"), [])

    def test_empty_file_returns_empty(self) -> None:
        p = self.dir / "empty.tsv"
        p.write_text("", encoding="utf-8")
        self.assertEqual(read_table(p), [])


class TestKv(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_read_kv(self) -> None:
        p = self.dir / "kv.tsv"
        p.write_text(
            "key\tvalue\nhostname\ttesthost\nos\tLinux\n",
            encoding="utf-8",
        )
        self.assertEqual(read_kv(p), {"hostname": "testhost", "os": "Linux"})

    def test_kv_multi_preserves_duplicates(self) -> None:
        p = self.dir / "dup.tsv"
        p.write_text(
            "key\tvalue\nnameserver\t1.1.1.1\nnameserver\t8.8.8.8\n",
            encoding="utf-8",
        )
        pairs = kv_multi(p)
        self.assertEqual(
            pairs, [("nameserver", "1.1.1.1"), ("nameserver", "8.8.8.8")]
        )


class TestLoadRaw(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_wide_table_not_registered_as_kv(self) -> None:
        (self.dir / "filesystem.inventory.tsv").write_text(
            "category\tpath\tsize_bytes\tmtime_epoch\textension\tflags\n"
            "document\ta.txt\t10\t1700000000\ttxt\t\n",
            encoding="utf-8",
        )
        (self.dir / "system.general.tsv").write_text(
            "key\tvalue\nhostname\thost1\n", encoding="utf-8"
        )
        data = load_raw(self.dir)
        self.assertEqual(len(data.table("filesystem.inventory")), 1)
        # Wide table must NOT produce a kv view (would collide on keys).
        self.assertNotIn("filesystem.inventory", data.kv)
        self.assertEqual(data.kvget("system.general", "hostname"), "host1")

    def test_missing_dir(self) -> None:
        data = load_raw(self.dir / "absent")
        self.assertEqual(data.tables, {})


class TestCsv(unittest.TestCase):
    def test_write_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "sub" / "out.csv"
            count = write_csv(
                [{"a": "1", "b": "x"}, {"a": "2"}], ["a", "b"], out
            )
            self.assertEqual(count, 2)
            text = out.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("a,b"))
            self.assertIn("2,", text.splitlines()[2])


class TestHelpers(unittest.TestCase):
    def test_epoch_to_iso(self) -> None:
        self.assertEqual(epoch_to_iso("1700000000"), "2023-11-14T22:13:20Z")

    def test_epoch_to_iso_invalid(self) -> None:
        self.assertEqual(epoch_to_iso("not-a-number"), "")
        self.assertEqual(epoch_to_iso(""), "")
        self.assertEqual(epoch_to_iso("0"), "")

    def test_human_bytes(self) -> None:
        self.assertEqual(human_bytes(0), "0 B")
        self.assertEqual(human_bytes(1024), "1.0 KiB")
        self.assertEqual(human_bytes(512), "512 B")
        self.assertTrue(human_bytes(5 * 1024**3).endswith("GiB"))


if __name__ == "__main__":
    unittest.main()
