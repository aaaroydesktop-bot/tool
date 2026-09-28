"""Tests for core.netutil — pure parsing logic, no dependencies."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import netutil


class TestParsePorts(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(netutil.parse_ports("22"), [22])

    def test_int_passthrough(self):
        self.assertEqual(netutil.parse_ports(443), [443])

    def test_comma_list_is_sorted_and_deduped(self):
        self.assertEqual(netutil.parse_ports("443,22,80,22"), [22, 80, 443])

    def test_range_is_inclusive(self):
        self.assertEqual(netutil.parse_ports("78-82"), [78, 79, 80, 81, 82])

    def test_reversed_range_is_normalised(self):
        self.assertEqual(netutil.parse_ports("82-78"), [78, 79, 80, 81, 82])

    def test_whitespace_and_spaces_are_tolerated(self):
        self.assertEqual(netutil.parse_ports(" 22 , 80 "), [22, 80])

    def test_preset_names(self):
        self.assertEqual(netutil.parse_ports("web"), sorted(set(netutil.WEB_PORTS)))

    def test_top_preset_matches_top_ports(self):
        self.assertEqual(netutil.parse_ports("top"), sorted(set(netutil.TOP_PORTS)))

    def test_default_is_top_ports(self):
        self.assertEqual(netutil.parse_ports(None), sorted(set(netutil.TOP_PORTS)))

    def test_all_covers_the_full_range(self):
        ports = netutil.parse_ports("all")
        self.assertEqual(ports[0], 1)
        self.assertEqual(ports[-1], netutil.MAX_PORT)
        self.assertEqual(len(ports), netutil.MAX_PORT)

    def test_mixed_expression(self):
        self.assertEqual(netutil.parse_ports("web,9001,1-2"), [1, 2, 80, 81, 88, 443,
                                                               8000, 8008, 8080, 8081,
                                                               8443, 8888, 9000, 9001,
                                                               9443])

    def test_rejects_out_of_range(self):
        for bad in ("0", "70000", "65536-70000"):
            with self.assertRaises(ValueError):
                netutil.parse_ports(bad)

    def test_rejects_garbage(self):
        for bad in ("http", "1-2-3", "", " "):
            with self.assertRaises(ValueError):
                netutil.parse_ports(bad)

    def test_sequence_input(self):
        self.assertEqual(netutil.parse_ports([80, 22, 80]), [22, 80])


class TestFormatPorts(unittest.TestCase):
    def test_collapses_runs(self):
        self.assertEqual(netutil.format_ports([1, 2, 3, 5, 9, 10]), "1-3,5,9-10")

    def test_single_port(self):
        self.assertEqual(netutil.format_ports([80]), "80")

    def test_empty(self):
        self.assertEqual(netutil.format_ports([]), "")

    def test_round_trip(self):
        ports = netutil.parse_ports("1-10,22,80,100-105")
        self.assertEqual(netutil.parse_ports(netutil.format_ports(ports)), ports)


class TestParseTarget(unittest.TestCase):
    def test_bare_host(self):
        self.assertEqual(netutil.parse_target("example.com"), ("example.com", None))

    def test_uppercase_is_lowered(self):
        self.assertEqual(netutil.parse_target("Example.COM"), ("example.com", None))

    def test_host_and_port(self):
        self.assertEqual(netutil.parse_target("example.com:8443"), ("example.com", 8443))

    def test_ipv4(self):
        self.assertEqual(netutil.parse_target("192.168.0.1"), ("192.168.0.1", None))

    def test_scheme_is_stripped(self):
        self.assertEqual(
            netutil.parse_target("https://example.com/path?q=1"),
            ("example.com", None),
        )

    def test_scheme_port_and_path(self):
        self.assertEqual(
            netutil.parse_target("http://example.com:8080/admin"),
            ("example.com", 8080),
        )

    def test_userinfo_is_stripped(self):
        self.assertEqual(netutil.parse_target("user:pass@example.com"), ("example.com", None))

    def test_trailing_dot_is_removed(self):
        self.assertEqual(netutil.parse_target("example.com."), ("example.com", None))

    def test_bracketed_ipv6_with_port(self):
        self.assertEqual(netutil.parse_target("[::1]:443"), ("::1", 443))

    def test_bracketed_ipv6_without_port(self):
        self.assertEqual(netutil.parse_target("[2001:db8::1]"), ("2001:db8::1", None))

    def test_empty_raises(self):
        for bad in ("", "   ", "http://"):
            with self.assertRaises(ValueError):
                netutil.parse_target(bad)

    def test_invalid_port_raises(self):
        with self.assertRaises(ValueError):
            netutil.parse_target("example.com:99999")


class TestCleanTargets(unittest.TestCase):
    def test_dedupes_and_preserves_order(self):
        values = ["b.com", "a.com", "b.com", ""]
        self.assertEqual(netutil.clean_targets(values), ["b.com", "a.com"])

    def test_skips_comments(self):
        self.assertEqual(netutil.clean_targets(["# note", "a.com"]), ["a.com"])

    def test_normalises_duplicates_written_differently(self):
        self.assertEqual(netutil.clean_targets(["A.com", "a.com:80"]), ["a.com"])

    def test_none_is_empty(self):
        self.assertEqual(netutil.clean_targets(None), [])


class TestValidation(unittest.TestCase):
    def test_is_ip(self):
        self.assertTrue(netutil.is_ip("10.0.0.1"))
        self.assertTrue(netutil.is_ip("::1"))
        self.assertFalse(netutil.is_ip("300.1.1.1"))
        self.assertFalse(netutil.is_ip("example.com"))

    def test_is_valid_host(self):
        self.assertTrue(netutil.is_valid_host("example.com"))
        self.assertTrue(netutil.is_valid_host("10.0.0.1"))
        self.assertFalse(netutil.is_valid_host("-bad.com"))
        self.assertFalse(netutil.is_valid_host(""))
        self.assertFalse(netutil.is_valid_host("a" * 300))

    def test_gateway_for(self):
        self.assertEqual(netutil.gateway_for("192.168.1.55"), "192.168.1.1")
        self.assertIsNone(netutil.gateway_for("example.com"))

    def test_gateway_for_custom_prefix(self):
        self.assertEqual(netutil.gateway_for("10.5.9.9", prefix=16), "10.5.0.1")


class TestFormatting(unittest.TestCase):
    def test_human_duration(self):
        self.assertEqual(netutil.human_duration(None), "n/a")
        self.assertEqual(netutil.human_duration(0.25), "250 ms")
        self.assertEqual(netutil.human_duration(2.5), "2.50 s")
        self.assertEqual(netutil.human_duration(90), "1m 30s")

    def test_human_bytes(self):
        self.assertEqual(netutil.human_bytes(512), "512.00 B")
        self.assertEqual(netutil.human_bytes(2048), "2.00 KB")
        self.assertEqual(netutil.human_bytes(None), "n/a")

    def test_human_bitrate(self):
        self.assertEqual(netutil.human_bitrate(0.5), "500 Kbps")
        self.assertEqual(netutil.human_bitrate(12.345), "12.35 Mbps")
        self.assertEqual(netutil.human_bitrate(None), "n/a")


if __name__ == "__main__":
    unittest.main()
