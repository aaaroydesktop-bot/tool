"""Tests for core.report — building, rendering and writing reports."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import report as reportlib


def sample_report() -> dict:
    report = reportlib.new_report("port_scan", "example.com", ip="93.184.216.34")
    reportlib.add_finding(report, port=22, state="open", service="SSH", banner="OpenSSH_9.6")
    reportlib.add_finding(report, port=443, state="open", service="HTTPS",
                          risk="plaintext FTP")
    reportlib.add_error(report, "port 9999 timed out")
    return reportlib.finish(report, 1.25, open=2, filtered=1, closed=10)


class TestBuilding(unittest.TestCase):
    def test_new_report_shape(self):
        report = reportlib.new_report("ping_test", "1.1.1.1")
        for key in ("tool", "version", "kind", "target", "started",
                    "findings", "errors", "meta", "summary"):
            self.assertIn(key, report)
        self.assertEqual(report["kind"], "ping_test")
        self.assertEqual(report["target"], "1.1.1.1")

    def test_meta_is_copied_not_shared(self):
        extra = {"a": 1}
        report = reportlib.new_report("x", "y", **extra)
        extra["a"] = 2
        self.assertEqual(report["meta"]["a"], 1)

    def test_add_finding_and_error(self):
        report = reportlib.new_report("x", "y")
        self.assertEqual(reportlib.add_finding(report, port=80), {"port": 80})
        reportlib.add_error(report, ValueError("boom"))
        self.assertEqual(report["errors"], ["boom"])

    def test_finish_records_duration_and_summary(self):
        report = reportlib.finish(reportlib.new_report("x", "y"), 0.7891, open=3)
        self.assertEqual(report["duration"], 0.789)
        self.assertEqual(report["summary"]["open"], 3)
        self.assertIn("finished", report)


class TestRendering(unittest.TestCase):
    def setUp(self):
        self.report = sample_report()

    def test_json_round_trips(self):
        payload = json.loads(reportlib.render(self.report, "json"))
        self.assertEqual(payload["target"], "example.com")
        self.assertEqual(len(payload["findings"]), 2)
        self.assertEqual(payload["summary"]["open"], 2)

    def test_markdown_contains_target_and_rows(self):
        text = reportlib.render(self.report, "md")
        self.assertIn("# NetScan report", text)
        self.assertIn("`example.com`", text)
        self.assertIn("| port | state | service |", text)
        self.assertIn("OpenSSH_9.6", text)
        self.assertIn("port 9999 timed out", text)

    def test_html_is_self_contained_and_escaped(self):
        report = reportlib.new_report("x", "<script>alert(1)</script>")
        reportlib.add_finding(report, port=80)
        html = reportlib.render(report, "html")
        self.assertTrue(html.startswith("<!DOCTYPE html>"))
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_csv_columns_follow_findings(self):
        lines = reportlib.render(self.report, "csv").strip().splitlines()
        self.assertEqual(lines[0], "port,state,service,banner,risk")
        self.assertEqual(len(lines), 3)

    def test_txt_summary(self):
        text = reportlib.render(self.report, "txt")
        self.assertIn("port_scan", text)
        self.assertIn("open=2", text)

    def test_alias_formats(self):
        self.assertEqual(reportlib.render(self.report, "markdown"),
                         reportlib.render(self.report, "md"))
        self.assertEqual(reportlib.render(self.report, "text"),
                         reportlib.render(self.report, "txt"))

    def test_unknown_format_raises(self):
        with self.assertRaises(ValueError):
            reportlib.render(self.report, "docx")

    def test_render_handles_missing_findings(self):
        report = reportlib.new_report("x", "y")
        self.assertIn("Findings (0)", reportlib.render(report, "html"))
        self.assertEqual(reportlib.render(report, "csv").strip(), "result")


class TestWriting(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="netscan-test-")
        self.report = sample_report()

    def tearDown(self):
        shutil.rmtree(self.directory, ignore_errors=True)

    def test_write_returns_absolute_path_and_creates_dirs(self):
        nested = os.path.join(self.directory, "deep", "nested")
        path = reportlib.write(self.report, fmt="json", directory=nested)
        self.assertTrue(os.path.isabs(path))
        self.assertTrue(os.path.exists(path))

    def test_write_then_load(self):
        path = reportlib.write(self.report, fmt="json", directory=self.directory)
        self.assertEqual(reportlib.load(path)["target"], "example.com")

    def test_explicit_path_is_respected(self):
        target = os.path.join(self.directory, "explicit.md")
        path = reportlib.write(self.report, fmt="md", path=target)
        self.assertEqual(path, os.path.abspath(target))
        with open(path, encoding="utf-8") as handle:
            self.assertIn("NetScan report", handle.read())

    def test_generated_name_contains_kind_and_target(self):
        path = reportlib.write(self.report, fmt="json", directory=self.directory)
        name = os.path.basename(path)
        self.assertTrue(name.startswith("port_scan_example.com_"))

    def test_latest_orders_newest_first(self):
        first = reportlib.write(self.report, fmt="json", directory=self.directory)
        second = reportlib.write(self.report, fmt="md", directory=self.directory)
        newest = reportlib.latest(self.directory, limit=1)
        self.assertEqual(newest, [max(first, second, key=os.path.getmtime)])

    def test_latest_on_missing_directory(self):
        self.assertEqual(reportlib.latest(os.path.join(self.directory, "nope")), [])

    def test_slug_sanitises(self):
        self.assertEqual(reportlib.slug("a b/c:d"), "a_b_c_d")
        self.assertEqual(reportlib.slug("///"), "scan")
        self.assertEqual(len(reportlib.slug("x" * 200)), 60)

    def test_all_declared_formats_render(self):
        for fmt in reportlib.FORMATS:
            with self.subTest(fmt=fmt):
                self.assertTrue(reportlib.render(self.report, fmt))

    def test_csv_file_uses_single_crlf(self):
        """Regression: Windows newline translation used to produce CRCRLF."""
        path = reportlib.write(self.report, fmt="csv", directory=self.directory)
        with open(path, "rb") as handle:
            raw = handle.read()
        self.assertNotIn(b"\r\r\n", raw)
        self.assertIn(b"port,state", raw)

    def test_text_reports_keep_lf_endings(self):
        path = reportlib.write(self.report, fmt="md", directory=self.directory)
        with open(path, "rb") as handle:
            raw = handle.read()
        self.assertNotIn(b"\r\n", raw)


if __name__ == "__main__":
    unittest.main()
