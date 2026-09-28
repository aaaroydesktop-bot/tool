"""
Deterministic tests for the scan engine.

Real sockets behave differently per platform (Windows returns WSAEWOULDBLOCK
for a refused connect when a timeout is set, POSIX returns ECONNREFUSED, some
firewalls silently drop), so the classification logic is tested against fake
sockets instead of hoping the network cooperates.
"""

from __future__ import annotations

import os
import sys
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tests import rich_stub  # noqa: E402

rich_stub.install()

from modules.network import scanner  # noqa: E402


class FakeSocket:
    """Minimal socket double: records calls, returns canned results."""

    def __init__(self, connect_ex=0, so_error=0, recv_data=b"", timeout_note=None):
        self.connect_ex_result = connect_ex
        self.so_error = so_error
        self.recv_data = recv_data
        self.timeout_note = timeout_note or TimeoutError("timed out")
        self.closed = False
        self.sent = []
        self.timeout = None
        self.addresses = []

    def settimeout(self, value):
        self.timeout = value

    def connect_ex(self, address):
        self.addresses.append(address)
        if isinstance(self.connect_ex_result, Exception):
            raise self.connect_ex_result
        return self.connect_ex_result

    def getsockopt(self, level, option):
        return self.so_error

    def recv(self, size):
        if isinstance(self.recv_data, Exception):
            raise self.recv_data
        return self.recv_data

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


class FakeSocketModule(types.SimpleNamespace):
    """Stands in for the ``socket`` module inside scanner."""

    AF_INET = 2
    SOCK_STREAM = 1
    SOL_SOCKET = 65535
    SO_ERROR = 4103
    timeout = TimeoutError

    def __init__(self, factory):
        super().__init__(socket=factory, gethostbyname=lambda host: "127.0.0.1")

    @staticmethod
    def gethostbyaddr(address):
        raise OSError("no reverse")


class FakeSelect:
    def __init__(self, writable=False, exceptional=False):
        self.writable = writable
        self.exceptional = exceptional

    def select(self, readers, writers, errors, timeout):
        return [], list(writers) if self.writable else [], \
            list(errors) if self.exceptional else []


def patch(factory, writable=False, exceptional=False):
    """Patch scanner's socket + select for the duration of a test."""
    socket_module = FakeSocketModule(factory)
    return mock.patch.multiple(
        scanner,
        socket=socket_module,
        select=FakeSelect(writable, exceptional),
    )


class TestPortClassification(unittest.TestCase):
    def test_successful_connect_is_open(self):
        with patch(lambda *a: FakeSocket(connect_ex=0)):
            result = scanner.scan_port("127.0.0.1", 80, tls=False)
        self.assertEqual(result["state"], "open")

    def test_refused_connect_is_closed(self):
        with patch(lambda *a: FakeSocket(connect_ex=111)):
            self.assertIsNone(scanner.scan_port("127.0.0.1", 80, tls=False))

    def test_macos_refused_code_is_closed(self):
        with patch(lambda *a: FakeSocket(connect_ex=61)):
            self.assertIsNone(scanner.scan_port("127.0.0.1", 80, tls=False))

    def test_windows_refused_via_so_error_is_closed(self):
        """10061 is what SO_ERROR holds after WSAEWOULDBLOCK + RST."""
        with patch(lambda *a: FakeSocket(connect_ex=10035, so_error=10061),
                   writable=True):
            self.assertIsNone(scanner.scan_port("127.0.0.1", 80, tls=False))

    def test_windows_silent_drop_is_filtered(self):
        with patch(lambda *a: FakeSocket(connect_ex=10035), writable=False):
            result = scanner.scan_port("127.0.0.1", 80, tls=False)
        self.assertEqual(result["state"], "filtered")

    def test_incomplete_connect_that_then_succeeds_is_open(self):
        with patch(lambda *a: FakeSocket(connect_ex=115, so_error=0), writable=True):
            result = scanner.scan_port("127.0.0.1", 80, tls=False)
        self.assertEqual(result["state"], "open")

    def test_unknown_error_code_is_filtered(self):
        with patch(lambda *a: FakeSocket(connect_ex=999)):
            result = scanner.scan_port("127.0.0.1", 80, tls=False)
        self.assertEqual(result["state"], "filtered")

    def test_connect_exception_is_not_a_finding(self):
        with patch(lambda *a: FakeSocket(connect_ex=OSError("boom"))):
            self.assertIsNone(scanner.scan_port("127.0.0.1", 80, tls=False))

    def test_failed_connect_socket_is_always_closed(self):
        created = FakeSocket(connect_ex=10035)
        with patch(lambda *a: created):
            scanner.scan_port("127.0.0.1", 80, tls=False)
        self.assertTrue(created.closed)

    def test_open_port_reports_service_and_risk(self):
        with patch(lambda *a: FakeSocket(connect_ex=0, recv_data=b"")):
            result = scanner.scan_port("127.0.0.1", 23, tls=False)
        self.assertEqual(result["service"], "TELNET")
        self.assertIn("plaintext", result["risk"])

    def test_banner_can_be_disabled(self):
        with patch(lambda *a: FakeSocket(connect_ex=0, recv_data=b"SSH-2.0-x")):
            with_banner = scanner.scan_port("127.0.0.1", 22, tls=False)
            without = scanner.scan_port("127.0.0.1", 22, tls=False, banner=False)
        self.assertIn("banner", with_banner)
        self.assertNotIn("banner", without)


class TestBannerProbe(unittest.TestCase):
    def test_reads_the_first_line(self):
        sock = FakeSocket(recv_data=b"SSH-2.0-OpenSSH_9.6\r\nmore junk")
        self.assertEqual(scanner.probe_banner(sock, "h", 22, 1.0), "SSH-2.0-OpenSSH_9.6")

    def test_empty_response(self):
        self.assertEqual(scanner.probe_banner(FakeSocket(recv_data=b""), "h", 22, 1.0), "")

    def test_timeout_is_swallowed(self):
        sock = FakeSocket(recv_data=TimeoutError("nope"))
        self.assertEqual(scanner.probe_banner(sock, "h", 22, 1.0), "")

    def test_http_port_gets_a_head_request(self):
        sock = FakeSocket(recv_data=b"HTTP/1.1 200 OK\r\n")
        scanner.probe_banner(sock, "example.com", 80, 1.0)
        self.assertEqual(len(sock.sent), 1)
        self.assertTrue(sock.sent[0].startswith(b"HEAD / HTTP/1.0"))
        self.assertIn(b"example.com", sock.sent[0])

    def test_binary_garbage_is_ignored(self):
        sock = FakeSocket(recv_data=b"\xff\xfe\x00\x01")
        self.assertTrue(isinstance(scanner.probe_banner(sock, "h", 22, 1.0), str))


class TestScanPorts(unittest.TestCase):
    def _scan(self, connect_ex, writable=False, keep_filtered=False):
        with patch(lambda *a: FakeSocket(connect_ex=connect_ex), writable=writable):
            return scanner.scan_ports(
                "example.com", [80, 81, 82], timeout=0.01, workers=1,
                show_progress=False, keep_filtered=keep_filtered,
            )

    def test_summary_counts(self):
        report = self._scan(111)
        self.assertEqual(report["summary"]["open"], 0)
        self.assertEqual(report["summary"]["closed"], 3)
        self.assertTrue(report["summary"]["resolved"])

    def test_filtered_counted_separately(self):
        report = self._scan(10035)
        self.assertEqual(report["summary"]["filtered"], 3)
        self.assertEqual(report["summary"]["closed"], 0)

    def test_filtered_list_is_opt_in(self):
        report = self._scan(10035)
        self.assertNotIn("filtered", report)
        kept = self._scan(10035, keep_filtered=True)
        self.assertEqual(kept["filtered"], [80, 81, 82])

    def test_findings_are_sorted_by_port(self):
        report = self._scan(0)
        self.assertEqual([f["port"] for f in report["findings"]], [80, 81, 82])

    def test_bad_port_spec_is_reported_not_raised(self):
        report = scanner.scan_ports("example.com", "bogus", timeout=0.01)
        self.assertTrue(report["errors"])
        self.assertEqual(report["summary"]["open"], 0)

    def test_unresolvable_target_is_reported(self):
        socket_module = FakeSocketModule(lambda *a: FakeSocket())

        def boom(host):
            raise OSError("name resolution failed")

        socket_module.gethostbyname = boom
        with mock.patch.object(scanner, "socket", socket_module):
            report = scanner.scan_ports("nope.invalid", [80], timeout=0.01)
        self.assertFalse(report["summary"]["resolved"])
        self.assertTrue(report["errors"])


class TestResolve(unittest.TestCase):
    def test_failure_returns_error_string(self):
        ip, error = scanner.resolve("this-host-does-not-exist.invalid")
        self.assertIsNone(ip)
        self.assertIsInstance(error, str)

    def test_loopback_resolves(self):
        ip, error = scanner.resolve("127.0.0.1")
        self.assertEqual(ip, "127.0.0.1")
        self.assertIsNone(error)


class TestDiff(unittest.TestCase):
    def test_opened_and_closed(self):
        before = {"target": "t", "started": "a",
                  "findings": [{"port": 22, "state": "open"}]}
        after = {"target": "t", "started": "b",
                 "findings": [{"port": 80, "state": "open"}]}
        changes = scanner.diff_reports(before, after)
        self.assertEqual(changes["summary"]["opened"], 1)
        self.assertEqual(changes["summary"]["closed"], 1)
        self.assertEqual(changes["summary"]["unchanged"], 0)
        self.assertEqual({f["change"] for f in changes["findings"]},
                         {"opened", "closed"})

    def test_no_change(self):
        report = {"target": "t", "started": "a", "findings": [{"port": 1, "state": "open"}]}
        changes = scanner.diff_reports(report, report)
        self.assertEqual(changes["findings"], [])
        self.assertEqual(changes["summary"]["unchanged"], 1)

    def test_open_port_set_ignores_filtered_entries(self):
        report = {"findings": [{"port": 1, "state": "open"},
                               {"port": 2, "state": "filtered"},
                               {"port": 3}]}
        self.assertEqual(scanner.open_port_set(report), {1})


if __name__ == "__main__":
    unittest.main()
