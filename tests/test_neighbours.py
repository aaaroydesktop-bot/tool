"""
Tests for ARP/neighbour parsing and MAC classification.

The fixtures below are copied from the real output shapes of
``/proc/net/arp``, ``ip neigh`` and the two ``arp -a`` flavours, because the
whole point of this module is that those formats differ per platform.
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests import rich_stub  # noqa: E402

rich_stub.install()

from core import console as console_module  # noqa: E402

console_module.configure(quiet=True)

from modules.network import localnet  # noqa: E402

PROC_FIXTURE = """IP address       HW type     Flags       HW address            Mask     Device
192.168.0.1      0x1         0x2         5c:8c:9f:aa:bb:01     *        wlan0
192.168.0.5      0x1         0x0         00:00:00:00:00:00     *        wlan0
192.168.0.7      0x1         0x2         02:11:22:aa:bb:cc     *        wlan0
10.0.0.9         0x1         0x2         B8:27:EB:00:00:01     *        eth0
"""

IPNEIGH_FIXTURE = """192.168.0.1 dev wlan0 lladdr 5c:8c:9f:aa:bb:01 REACHABLE
192.168.0.5 dev wlan0  FAILED
192.168.0.9 dev wlan0 lladdr 34:e8:94:11:22:33 STALE
192.168.0.11 dev wlan0  INCOMPLETE
fe80::1 dev wlan0 lladdr 5c:8c:9f:aa:bb:01 router
"""

WINDOWS_ARP = """Interface: 192.168.0.20 --- 0x8
  Internet Address      Physical Address      Type
  192.168.0.1           5c-8c-9f-aa-bb-01     dynamic
  192.168.0.7           02-11-22-aa-bb-cc     dynamic
  224.0.0.22            01-00-5e-00-00-16     static
"""

LINUX_ARP = """? (192.168.0.1) at 5c:8c:9f:aa:bb:01 [ether] on wlan0
? (192.168.0.7) at 02:11:22:aa:bb:cc [ether] on wlan0
"""


class TestParseProcArp(unittest.TestCase):
    def test_reads_real_rows(self):
        table = localnet.parse_neighbours(PROC_FIXTURE, "proc")
        self.assertEqual(table["192.168.0.1"], "5c:8c:9f:aa:bb:01")
        self.assertEqual(table["10.0.0.9"], "b8:27:eb:00:00:01")

    def test_skips_unresolved_entries(self):
        table = localnet.parse_neighbours(PROC_FIXTURE, "proc")
        self.assertNotIn("192.168.0.5", table)

    def test_finds_randomized_mac(self):
        table = localnet.parse_neighbours(PROC_FIXTURE, "proc")
        self.assertEqual(table["192.168.0.7"], "02:11:22:aa:bb:cc")

    def test_header_is_not_a_row(self):
        table = localnet.parse_neighbours(PROC_FIXTURE, "proc")
        self.assertEqual(len(table), 3)


class TestParseIpNeigh(unittest.TestCase):
    def test_reads_lladdr_rows(self):
        table = localnet.parse_neighbours(IPNEIGH_FIXTURE, "ip-neigh")
        self.assertEqual(table["192.168.0.1"], "5c:8c:9f:aa:bb:01")
        self.assertEqual(table["192.168.0.9"], "34:e8:94:11:22:33")

    def test_skips_failed_and_incomplete(self):
        table = localnet.parse_neighbours(IPNEIGH_FIXTURE, "ip-neigh")
        self.assertNotIn("192.168.0.5", table)
        self.assertNotIn("192.168.0.11", table)

    def test_ignores_ipv6(self):
        table = localnet.parse_neighbours(IPNEIGH_FIXTURE, "ip-neigh")
        self.assertFalse([ip for ip in table if ":" in ip])


class TestParseNetTools(unittest.TestCase):
    def test_windows_style_dashes(self):
        table = localnet.parse_neighbours(WINDOWS_ARP, "net-tools")
        self.assertEqual(table["192.168.0.1"], "5c:8c:9f:aa:bb:01")
        self.assertEqual(table["192.168.0.7"], "02:11:22:aa:bb:cc")

    def test_multicast_entries_are_dropped(self):
        """224.0.0.22 is IGMP chatter, not a device."""
        table = localnet.parse_neighbours(WINDOWS_ARP, "net-tools")
        self.assertNotIn("224.0.0.22", table)
        self.assertEqual(len(table), 2)

    def test_linux_parenthesised_at_format(self):
        table = localnet.parse_neighbours(LINUX_ARP, "net-tools")
        self.assertEqual(table["192.168.0.1"], "5c:8c:9f:aa:bb:01")
        self.assertEqual(table["192.168.0.7"], "02:11:22:aa:bb:cc")


class TestParseRobustness(unittest.TestCase):
    def test_empty_and_garbage(self):
        for text in ("", None, "garbage\n\n", "not an arp table at all"):
            with self.subTest(text=text):
                self.assertEqual(localnet.parse_neighbours(text, "proc"), {})
                self.assertEqual(localnet.parse_neighbours(text, "ip-neigh"), {})
                self.assertEqual(localnet.parse_neighbours(text, "net-tools"), {})

    def test_permission_denied_message_is_not_parsed(self):
        text = "cat: /proc/net/arp: Permission denied\n"
        self.assertEqual(localnet.parse_neighbours(text, "proc"), {})

    def test_short_or_malformed_macs_are_rejected(self):
        text = "192.168.0.1 0x1 0x2 5c:8c:9f:aa:bb * wlan0\n"
        self.assertEqual(localnet.parse_neighbours(text, "proc"), {})

    def test_duplicate_ip_keeps_last(self):
        text = ("192.168.0.1 0x1 0x2 5c:8c:9f:aa:bb:01 * wlan0\n"
                "192.168.0.1 0x1 0x2 5c:8c:9f:aa:bb:02 * wlan0\n")
        self.assertEqual(localnet.parse_neighbours(text, "proc")["192.168.0.1"],
                         "5c:8c:9f:aa:bb:02")


class TestMacClassification(unittest.TestCase):
    def test_randomized_detection(self):
        randomized = ["02:11:22:aa:bb:cc", "06:00:00:00:00:00", "9A:bb:cc:dd:ee:ff"]
        normal = ["5c:8c:9f:aa:bb:01", "b8:27:eb:00:00:01", "34:e8:94:11:22:33"]
        for mac in randomized:
            with self.subTest(mac=mac):
                self.assertTrue(localnet.is_randomized_mac(mac))
        for mac in normal:
            with self.subTest(mac=mac):
                self.assertFalse(localnet.is_randomized_mac(mac))

    def test_accepts_dashes_and_lowercase(self):
        self.assertTrue(localnet.is_randomized_mac("02-11-22-aa-bb-cc"))

    def test_invalid_input_is_not_classified(self):
        """Free text must not be mistaken for a MAC."""
        for value in ("", "zz", "nonsense", "de:ad", "5c:8c:9f"):
            with self.subTest(value=value):
                self.assertFalse(localnet.is_randomized_mac(value))
                self.assertFalse(localnet.is_multicast_mac(value))

    def test_multicast_detection(self):
        self.assertTrue(localnet.is_multicast_mac("01:00:5e:00:00:16"))
        self.assertFalse(localnet.is_multicast_mac("5c:8c:9f:aa:bb:01"))

    def test_mac_note(self):
        self.assertEqual(localnet.mac_note("02:11:22:aa:bb:cc"), "randomized")
        self.assertEqual(localnet.mac_note("01:00:5e:00:00:16"), "multicast/broadcast")
        self.assertEqual(localnet.mac_note("5c:8c:9f:aa:bb:01"), "")
        self.assertEqual(localnet.mac_note(""), "")


class TestVendorFor(unittest.TestCase):
    def test_known_oui(self):
        self.assertEqual(localnet.vendor_for("b8:27:eb:00:00:01"), "Raspberry Pi")

    def test_randomized_macs_have_no_vendor(self):
        """Randomized MACs must not be attributed to their OUI's owner."""
        self.assertEqual(localnet.vendor_for("02:11:22:aa:bb:cc"), "")

    def test_unknown_oui(self):
        self.assertEqual(localnet.vendor_for("00:00:01:00:00:01"), "")


class TestReadNeighbours(unittest.TestCase):
    def test_shape_and_types(self):
        cache = localnet.read_neighbours()
        self.assertIn("entries", cache)
        self.assertIn("sources", cache)
        self.assertIn("problems", cache)
        self.assertIsInstance(cache["entries"], dict)
        for entry in cache["sources"]:
            self.assertEqual(len(entry), 2)
        for problem in cache["problems"]:
            self.assertEqual(len(problem), 2)

    def test_arp_table_wrapper_returns_entries_only(self):
        self.assertIsInstance(localnet.arp_table(), dict)

    def test_every_mac_looks_normalised(self):
        for mac in localnet.read_neighbours()["entries"].values():
            parts = mac.split(":")
            self.assertEqual(len(parts), 6, mac)
            for part in parts:
                self.assertEqual(len(part), 2, mac)


class TestMacOnlyOutput(unittest.TestCase):
    """--mac-only must be pipeable, which means it must survive quieting."""

    def _capture(self, report, **kwargs):
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            localnet.present_arp(report, **kwargs)
        return buffer.getvalue()

    def test_rows_are_tab_separated_and_skip_missing_macs(self):
        report = {"findings": [
            {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"},
            {"ip": "10.0.0.2", "mac": ""},
            {"ip": "10.0.0.3", "mac": "11:22:33:44:55:66"},
        ]}
        output = self._capture(report, mac_only=True)
        self.assertEqual(output,
                         "10.0.0.1\taa:bb:cc:dd:ee:ff\n10.0.0.3\t11:22:33:44:55:66\n")

    def test_output_is_not_silenced_by_quiet_mode(self):
        """The test module configures quiet globally; rows must still appear."""
        self.assertTrue(console_module.is_quiet(), "test setup expects quiet mode")
        report = {"findings": [{"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"}]}
        self.assertIn("10.0.0.1\taa:bb:cc:dd:ee:ff", self._capture(report, mac_only=True))

    def test_empty_table_emits_nothing_on_stdout(self):
        self.assertEqual(self._capture({"findings": []}, mac_only=True), "")

    def test_without_mac_only_nothing_is_printed_when_quiet(self):
        report = {"findings": [{"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"}]}
        self.assertEqual(self._capture(report), "")


class TestArpReport(unittest.TestCase):
    def test_report_shape_without_scanning(self):
        report = localnet.arp_report(scan=False)
        self.assertEqual(report["kind"], "arp_table")
        for key in ("target", "findings", "summary", "errors", "meta"):
            self.assertIn(key, report)
        self.assertIn("entries", report["summary"])
        self.assertFalse(report["meta"]["swept"])

    def test_findings_have_ip_and_mac(self):
        report = localnet.arp_report(scan=False)
        for finding in report["findings"]:
            self.assertIn("ip", finding)
            self.assertIn("mac", finding)
            self.assertEqual(len(finding["mac"].split(":")), 6)

    def test_vendor_flag_adds_a_column(self):
        report = localnet.arp_report(scan=False, vendor=True)
        for finding in report["findings"]:
            self.assertIn("vendor", finding)

    def test_empty_cache_is_explained(self):
        """When nothing is readable the report must say so, not just be empty."""
        report = localnet.arp_report(scan=False)
        if not report["findings"]:
            self.assertTrue(report["errors"])
            self.assertIn("neighbour", report["errors"][0].lower())

    def test_mac_only_presentation_does_not_crash(self):
        import contextlib
        import io

        report = localnet.arp_report(scan=False)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.assertIs(localnet.present_arp(report, mac_only=True), report)

    def test_bad_network_is_ignored_gracefully(self):
        report = localnet.arp_report(network="not-a-subnet", scan=False)
        self.assertEqual(report["kind"], "arp_table")


class TestDiscover(unittest.TestCase):
    """192.0.2.0/30 is TEST-NET-1: unroutable, so no real host is touched."""

    def test_summary_reports_mac_coverage(self):
        report = localnet.discover("192.0.2.0/30", workers=4, timeout=0.05)
        self.assertEqual(report["kind"], "local_network_scan")
        self.assertIn("macs_found", report["summary"])
        self.assertIn("arp_sources", report["meta"])

    def test_findings_carry_mac_and_note_fields(self):
        report = localnet.discover("192.0.2.0/30", workers=4, timeout=0.05)
        for finding in report["findings"]:
            self.assertIn("mac", finding)
            self.assertIn("note", finding)

    def test_unknown_subnet_is_reported_without_sweeping(self):
        """Patch the detection so the test never probes the machine's own LAN."""
        from unittest import mock

        with mock.patch.object(localnet, "local_ip", return_value="127.0.0.1"), \
                mock.patch.object(localnet, "subnet_of", return_value=None):
            report = localnet.discover(None, workers=4, timeout=0.05)
        self.assertEqual(report["summary"]["devices"], 0)
        self.assertTrue(report["errors"])
        self.assertIn("subnet", report["errors"][0])


if __name__ == "__main__":
    unittest.main()
