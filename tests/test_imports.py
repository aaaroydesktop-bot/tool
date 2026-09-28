"""
Import-graph and wiring tests.

Only ``rich`` is a hard dependency, so when it is not installed this module
injects a minimal stand-in.  That keeps these tests runnable anywhere - CI,
a fresh Termux install before pip finishes, or a bare Python - while still
proving that every module imports and that the CLI is correctly wired.
"""

from __future__ import annotations

import os
import pathlib
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tests import rich_stub  # noqa: E402

_USING_STUB = rich_stub.install()

# Rendering is exercised elsewhere; keep these tests about wiring, not output.
from core import console as _console_module  # noqa: E402

_console_module.configure(quiet=True)


class TestImportGraph(unittest.TestCase):
    def test_core_modules_import(self):
        for module in ("core", "core.console", "core.utils", "core.netutil",
                       "core.environment", "core.report", "core.http",
                       "core.banner", "core.menu", "core.checker"):
            with self.subTest(module=module):
                __import__(module)

    def test_feature_modules_import(self):
        for module in ("modules", "modules.network", "modules.osint",
                       "modules.monitoring", "modules.history", "modules.firewall",
                       "modules.plugins", "modules.reporting", "modules.ai"):
            with self.subTest(module=module):
                __import__(module)

    def test_network_submodules_import(self):
        for module in ("scanner", "services", "dns", "geoip", "headers",
                       "subdomain", "localnet", "ping", "traceroute", "vendor",
                       "speedtest", "techdetect"):
            with self.subTest(module=module):
                __import__(f"modules.network.{module}")

    def test_cli_and_main_import(self):
        __import__("cli")
        __import__("main")

    def test_dead_network_module_is_gone(self):
        """modules/network.py used to shadow the real package."""
        self.assertFalse(os.path.exists(os.path.join(ROOT, "modules", "network.py")))

    def test_network_package_exports_are_real(self):
        from modules import network

        for name in network.__all__:
            with self.subTest(name=name):
                self.assertTrue(hasattr(network, name), f"missing export: {name}")

    def test_lazy_module_access(self):
        import modules

        self.assertIs(modules.history, modules.history)
        self.assertIs(getattr(modules, "reporting"), getattr(modules, "reporting"))
        with self.assertRaises(AttributeError):
            modules.nonexistent_module


class TestScannerAPI(unittest.TestCase):
    """Detailed engine cases live in test_scanner.py; this is a shape check."""

    def test_scan_ports_returns_report_shape(self):
        from modules.network import scanner

        report = scanner.scan_ports("127.0.0.1", [65000], timeout=0.05, workers=1)
        for key in ("kind", "target", "findings", "summary", "errors"):
            self.assertIn(key, report)
        self.assertEqual(report["kind"], "port_scan")

    def test_dns_lookup_is_aliased_to_the_dns_module(self):
        from modules import network
        from modules.network import dns

        self.assertIs(network.dns_lookup, dns.lookup)

    def test_report_objects_round_trip_through_json(self):
        import json

        from modules.network import scanner

        report = scanner.scan_ports("127.0.0.1", [65000], timeout=0.05, workers=1)
        self.assertEqual(json.loads(json.dumps(report))["target"], "127.0.0.1")


class TestServiceData(unittest.TestCase):
    def test_service_names(self):
        from modules.network import services

        self.assertEqual(services.service_name(22), "SSH")
        self.assertEqual(services.service_name(65000), "unknown")
        self.assertTrue(services.is_http_like(80))
        self.assertTrue(services.is_tls_like(443))
        self.assertIn("plaintext", services.risk_note(23))
        self.assertIsNone(services.risk_note(80))

    def test_smart_ports_match_the_service_map(self):
        from modules.network import services

        self.assertEqual(services.SMART_PORTS, sorted(services.COMMON_SERVICES))


class TestHotspotDetector(unittest.TestCase):
    def test_normalize_valid_and_invalid(self):
        from modules.network import vendor

        self.assertEqual(vendor.normalize("a0:02:dc:11:22:33"), "A0:02:DC:11:22:33")
        self.assertEqual(vendor.normalize("a002dc112233"), "A0:02:DC:11:22:33")
        with self.assertRaises(ValueError):
            vendor.normalize("nope")

    def test_offline_lookup_finds_a_vendor(self):
        from modules.network import vendor

        report = vendor.lookup("B8:27:EB:00:00:01", online=False)
        self.assertEqual(report["findings"][0]["vendor"], "Raspberry Pi")

    def test_offline_lookup_reports_unknown(self):
        from modules.network import vendor

        report = vendor.lookup("02:00:00:00:00:01", online=False)
        self.assertEqual(report["findings"][0]["vendor"], "unresolved")
        self.assertFalse(report["summary"]["found"])


class TestAiPlanner(unittest.TestCase):
    def test_scan_intent_with_ports(self):
        from modules.ai import plan

        result = plan("scan 192.168.1.1 ports 1-1024")
        self.assertEqual(result["argv"][:2], ["scan", "192.168.1.1"])
        self.assertIn("--ports", result["argv"])
        self.assertEqual(result["confidence"], "high")

    def test_full_scan_intent(self):
        from modules.ai import plan

        result = plan("scan example.com all ports")
        self.assertIn("--ports", result["argv"])
        self.assertIn("all", result["argv"])

    def test_local_intent_needs_no_target(self):
        from modules.ai import plan

        self.assertEqual(plan("show devices on my wifi")["argv"], ["local"])

    def test_missing_target_is_low_confidence(self):
        from modules.ai import plan

        result = plan("ping the server")
        self.assertEqual(result["argv"], [])
        self.assertEqual(result["confidence"], "low")

    def test_unknown_intent(self):
        from modules.ai import plan

        result = plan("make me a sandwich")
        self.assertIsNone(result["command"])
        self.assertEqual(result["confidence"], "low")

    def test_url_target_for_headers(self):
        from modules.ai import plan

        self.assertEqual(plan("grab http headers from example.com")["argv"],
                         ["headers", "example.com"])


class TestChecker(unittest.TestCase):
    def test_missing_returns_list(self):
        from core import checker

        self.assertEqual(checker.missing({"sys": "always there"}), [])
        self.assertEqual(checker.missing({"nope_xyz": "never there"}), ["nope_xyz"])

    def test_doctor_report_shape(self):
        from core import checker

        report = checker.doctor()
        self.assertEqual(report["kind"], "doctor")
        self.assertIn("healthy", report["summary"])
        self.assertTrue(report["findings"])
        for finding in report["findings"]:
            self.assertIn(finding["status"], ("ok", "warn", "fail"))


class TestVersionMetadata(unittest.TestCase):
    def test_label_matches_version_and_edition(self):
        from core import EDITION, VERSION_LABEL, __version__

        self.assertEqual(VERSION_LABEL, f"{__version__} {EDITION}")
        self.assertEqual(EDITION, "Pro")

    def test_reports_carry_version_and_edition(self):
        """``version`` stays machine-readable; the edition is a separate field."""
        from core import EDITION, __version__, report as reportlib

        report = reportlib.new_report("x", "y")
        self.assertEqual(report["version"], __version__)
        self.assertEqual(report["edition"], EDITION)
        self.assertNotIn(" ", report["version"], "version must be comparable")

    def test_cli_advertises_the_label(self):
        import cli

        from core import VERSION_LABEL

        parser = cli.build_parser()
        self.assertIn(VERSION_LABEL, parser.description)
        self.assertEqual(parser.prog, "netscan")

    def test_can_encode(self):
        from unittest import mock

        from core import banner as banner_module

        with mock.patch.object(banner_module, "_stdout_encoding", return_value="ascii"):
            self.assertTrue(banner_module._can_encode("plain ascii"))
            self.assertFalse(banner_module._can_encode("\u2588"))
        with mock.patch.object(banner_module, "_stdout_encoding", return_value="utf-8"):
            self.assertTrue(banner_module._can_encode("\u2588"))

    def test_logo_falls_back_to_ascii_when_needed(self):
        """A non-UTF-8 console used to crash the menu before it drew anything."""
        from unittest import mock

        from core import banner as banner_module

        for encoding, expected in (("utf-8", banner_module._LOGO_UNICODE),
                                   ("cp1252", banner_module._LOGO_ASCII),
                                   ("ascii", banner_module._LOGO_ASCII)):
            with self.subTest(encoding=encoding):
                with mock.patch.object(banner_module, "_stdout_encoding",
                                       return_value=encoding):
                    self.assertEqual(banner_module.logo(), expected)

    def test_ascii_logo_is_pure_ascii(self):
        from core import banner as banner_module

        self.assertTrue(banner_module._LOGO_ASCII.isascii())
        self.assertFalse(banner_module._LOGO_UNICODE.isascii())

    def test_banner_survives_a_hostile_encoding(self):
        from unittest import mock

        from core import banner as banner_module

        with mock.patch.object(banner_module, "_stdout_encoding", return_value="ascii"):
            banner_module.banner(show_logo=False)  # must not raise
        with mock.patch.object(banner_module, "logo",
                              side_effect=UnicodeEncodeError("ascii", "x", 0, 1, "boom")):
            banner_module.banner(show_logo=False)  # must not raise either

    def test_user_agent_tracks_the_version(self):
        from core import __version__
        from core.http import USER_AGENT

        self.assertIn(__version__, USER_AGENT)


class TestSourceHygiene(unittest.TestCase):
    """Guards two footguns that only show up on the target platform."""

    #: The banner is deliberate ASCII art and is the one exception.
    NON_ASCII_ALLOWED = {"banner.py"}

    def test_python_sources_stay_ascii(self):
        """A non-ASCII glyph renders as mojibake on non-UTF-8 Termux consoles."""
        offenders: dict[str, list[str]] = {}
        for path in pathlib.Path(ROOT).rglob("*.py"):
            if "__pycache__" in path.parts or path.name in self.NON_ASCII_ALLOWED:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            chars = sorted({char for char in text if ord(char) > 127})
            if chars:
                offenders[str(path.relative_to(ROOT))] = [
                    f"U+{ord(char):04X}" for char in chars
                ]
        self.assertEqual(offenders, {}, f"non-ASCII characters found: {offenders}")

    def test_shell_scripts_use_lf_endings(self):
        """CRLF makes Termux fail with 'bad interpreter: ^M'."""
        for name in ("install.sh", "bin/netscan"):
            with self.subTest(script=name):
                raw = (pathlib.Path(ROOT) / name).read_bytes()
                self.assertNotIn(b"\r\n", raw)
                self.assertTrue(raw.startswith(b"#!"), "missing shebang")

    def test_shell_scripts_use_the_termux_shebang(self):
        """Termux has no /usr/bin, so '#! /usr/bin/env bash' cannot work."""
        for name in ("install.sh", "bin/netscan"):
            with self.subTest(script=name):
                first = (pathlib.Path(ROOT) / name).read_bytes().splitlines()[0]
                self.assertIn(b"com.termux", first)


class TestMenuRegistry(unittest.TestCase):
    def test_numbers_are_contiguous_and_handlers_callable(self):
        import main

        entries, display = main._numbered(main.build_registry())
        self.assertEqual(sorted(entries), list(range(1, len(entries) + 1)))
        for number, (label, handler) in entries.items():
            self.assertTrue(label, f"#{number} has no label")
            self.assertTrue(callable(handler), f"#{number} ({label}) is not callable")
        self.assertEqual(sum(len(items) for _, items in display), len(entries))

    def test_arp_is_reachable_from_the_menu(self):
        import main

        _, display = main._numbered(main.build_registry())
        labels = [label.lower() for _, items in display for _, label in items]
        self.assertTrue(any("mac" in label for label in labels),
                        "no menu entry mentions MAC addresses")

    def test_every_menu_entry_has_a_unique_label(self):
        import main

        _, display = main._numbered(main.build_registry())
        labels = [label for _, items in display for _, label in items]
        self.assertEqual(len(labels), len(set(labels)))


class TestCliWiring(unittest.TestCase):
    def setUp(self):
        import cli

        self.cli = cli
        self.parser = cli.build_parser()

    def test_every_command_has_a_handler(self):
        actions = [
            action for action in self.parser._subparsers._group_actions
        ][0]
        for name in actions.choices:
            with self.subTest(command=name):
                self.assertIn(name, self.cli.HANDLERS)

    def test_no_handler_is_orphaned(self):
        actions = [action for action in self.parser._subparsers._group_actions][0]
        for name in self.cli.HANDLERS:
            self.assertIn(name, actions.choices)

    def test_parse_scan_with_options(self):
        args = self.parser.parse_args(
            ["scan", "example.com", "--ports", "web", "-o", "out.html", "--json"]
        )
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.targets, ["example.com"])
        self.assertEqual(args.ports, "web")
        self.assertEqual(args.output, "out.html")
        self.assertTrue(args.json)

    def test_parse_defaults(self):
        args = self.parser.parse_args(["scan", "example.com"])
        self.assertEqual(args.ports, "top")
        self.assertFalse(args.json)
        self.assertFalse(args.save)

    def test_parse_history_show(self):
        args = self.parser.parse_args(["history", "--show", "7"])
        self.assertEqual(args.show, 7)

    def test_parse_block_dry_run(self):
        args = self.parser.parse_args(["block", "10.0.0.1", "--dry-run"])
        self.assertEqual((args.command, args.ip, args.dry_run),
                         ("block", "10.0.0.1", True))

    def test_targets_from_file(self):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write("example.com\n# comment\n10.0.0.1\n\n")
            path = handle.name
        try:
            args = self.parser.parse_args(["scan", "--targets-file", path])
            self.assertEqual(self.cli._targets_from_args(args),
                             ["example.com", "10.0.0.1"])
        finally:
            os.remove(path)

    def test_usage_error_when_no_targets(self):
        args = self.parser.parse_args(["scan"])
        self.assertEqual(self.cli.cmd_scan(args), self.cli.EXIT_USAGE)

    def test_bad_port_spec_is_usage_error(self):
        args = self.parser.parse_args(["scan", "example.com", "--ports", "nope"])
        self.assertEqual(self.cli.cmd_scan(args), self.cli.EXIT_USAGE)

    def test_history_actions_reference_real_commands(self):
        actions = [action for action in self.parser._subparsers._group_actions][0]
        for command in self.cli.HISTORY_ACTIONS:
            with self.subTest(command=command):
                self.assertIn(command, actions.choices)


class TestReportHelpers(unittest.TestCase):
    def test_reporting_shim_round_trips(self):
        import tempfile

        from modules import reporting
        from core import report as reportlib

        report = reportlib.new_report("shim", "target")
        reportlib.add_finding(report, port=80)
        with tempfile.TemporaryDirectory() as directory:
            path = reporting.save_report(report, os.path.join(directory, "x.json"))
            self.assertEqual(reportlib.load(path)["target"], "target")


if __name__ == "__main__":
    unittest.main()
