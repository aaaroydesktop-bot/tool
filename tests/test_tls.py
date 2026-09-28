"""
Tests for the TLS audit engine in :mod:`modules.network.tls`.

Everything that is pure logic is tested directly.  The network is touched only
once, against a closed loopback port, to prove that an unreachable host degrades
into a report instead of raising.  That keeps the suite offline and instant.
"""

from __future__ import annotations

import datetime
import os
import ssl
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests import rich_stub  # noqa: E402

rich_stub.install()

from core import console as console_module  # noqa: E402

console_module.configure(quiet=True)

from modules.network import tls  # noqa: E402

NOW = datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)


# --------------------------------------------------------------------------
# PURE HELPERS
# --------------------------------------------------------------------------


class TestProtocolEnum(unittest.TestCase):
    def test_known_versions(self):
        self.assertIs(tls.protocol_enum("TLSv1.3"), ssl.TLSVersion.TLSv1_3)
        self.assertIs(tls.protocol_enum("TLSv1.2"), ssl.TLSVersion.TLSv1_2)

    def test_unknown_name_is_none(self):
        self.assertIsNone(tls.protocol_enum("SSLv3"))
        self.assertIsNone(tls.protocol_enum(""))


class TestDaysRemaining(unittest.TestCase):
    def test_future(self):
        after = NOW + datetime.timedelta(days=30)
        self.assertEqual(tls.days_remaining(after, now=NOW), 30)

    def test_past_is_negative(self):
        after = NOW - datetime.timedelta(days=1)
        self.assertEqual(tls.days_remaining(after, now=NOW), -1)

    def test_boundary_is_zero(self):
        self.assertEqual(tls.days_remaining(NOW, now=NOW), 0)

    def test_partial_days_round_towards_zero(self):
        after = NOW + datetime.timedelta(hours=23)
        self.assertEqual(tls.days_remaining(after, now=NOW), 0)

    def test_naive_timestamp_is_treated_as_utc(self):
        naive = datetime.datetime(2026, 1, 31, 12, 0, 0)
        self.assertEqual(tls.days_remaining(naive, now=NOW), 30)


class TestWeakCipherReason(unittest.TestCase):
    def test_rc4_and_3des_and_md5(self):
        self.assertIsNotNone(tls.weak_cipher_reason("TLS_RSA_WITH_RC4_128_SHA"))
        self.assertIsNotNone(
            tls.weak_cipher_reason("TLS_RSA_WITH_3DES_EDE_CBC_SHA"))
        self.assertIsNotNone(
            tls.weak_cipher_reason("TLS_RSA_WITH_NULL_MD5"))

    def test_modern_suites_are_clean(self):
        for name in ("TLS_AES_128_GCM_SHA256",
                     "TLS_CHACHA20_POLY1305_SHA256",
                     "ECDHE-ECDSA-AES128-GCM-SHA256",
                     "ECDHE-RSA-AES256-GCM-SHA384"):
            with self.subTest(name=name):
                self.assertIsNone(tls.weak_cipher_reason(name))

    def test_none_and_empty(self):
        self.assertIsNone(tls.weak_cipher_reason(None))
        self.assertIsNone(tls.weak_cipher_reason(""))


class TestForwardSecrecy(unittest.TestCase):
    def test_tls13_and_ephemeral_suites_have_it(self):
        for name in ("TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256",
                     "ECDHE-RSA-AES256-GCM-SHA384", "DHE-RSA-AES256-GCM-SHA384"):
            with self.subTest(name=name):
                self.assertTrue(tls.has_forward_secrecy(name))

    def test_static_rsa_does_not(self):
        for name in ("TLS_RSA_WITH_AES_256_GCM_SHA384",
                     "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"):
            with self.subTest(name=name):
                self.assertFalse(tls.has_forward_secrecy(name))

    def test_missing_name(self):
        self.assertFalse(tls.has_forward_secrecy(None))


class TestGrade(unittest.TestCase):
    """The ladder, in order: A+ A A- B+ B B- C+ C C- D E F."""

    def _grade(self, **overrides):
        kwargs = dict(trusted=True, days_left=365, legacy=False, weak=False,
                      fs_missing=False, key_bits=2048, weak_signature=False)
        kwargs.update(overrides)
        return tls.grade(**kwargs)

    def test_clean_configuration_is_a_plus(self):
        self.assertEqual(self._grade(), "A+")

    def test_untrusted_is_f(self):
        self.assertEqual(self._grade(trusted=False), "F")

    def test_expired_is_f(self):
        self.assertEqual(self._grade(days_left=-1), "F")

    def test_self_signed_costs_one_step(self):
        self.assertEqual(self._grade(self_signed=True), "A")

    def test_legacy_protocol_floors_at_b_plus(self):
        self.assertEqual(self._grade(legacy=True), "B+")

    def test_weak_cipher_demotes_twice(self):
        self.assertEqual(self._grade(weak=True), "A-")

    def test_missing_forward_secrecy_floors_at_b_minus(self):
        self.assertEqual(self._grade(fs_missing=True), "B-")

    def test_weak_signature_floors_at_c(self):
        self.assertEqual(self._grade(weak_signature=True), "C")

    def test_small_rsa_key_demotes_once(self):
        self.assertEqual(self._grade(key_bits=1024), "A")

    def test_ec_keys_are_not_penalised(self):
        """A 256-bit EC key is strong; pass None, not 256."""
        self.assertEqual(self._grade(key_bits=None), "A+")

    def test_expiring_soon_floors_at_c_plus(self):
        self.assertEqual(self._grade(days_left=10), "C+")

    def test_expiring_within_a_month_floors_at_b(self):
        self.assertEqual(self._grade(days_left=20), "B")

    def test_the_worst_case_never_overflows_the_ladder(self):
        result = self._grade(trusted=False, days_left=-5, legacy=True, weak=True,
                             fs_missing=True, key_bits=512, weak_signature=True,
                             self_signed=True)
        self.assertIn(result, tls.GRADE_LADDER)


class TestClassifyTrust(unittest.TestCase):
    def test_each_reason(self):
        cases = {
            "Hostname mismatch, certificate is not valid for 'x'": "hostname-mismatch",
            "IP address mismatch": "hostname-mismatch",
            "certificate has expired": "expired",
            "certificate is not yet valid": "not-yet-valid",
            "self-signed certificate": "self-signed",
            "self signed certificate in certificate chain": "self-signed",
            "unable to get local issuer certificate": "unknown-issuer",
        }
        for message, expected in cases.items():
            with self.subTest(message=message):
                self.assertEqual(tls.classify_trust(message), expected)

    def test_fallback(self):
        self.assertEqual(tls.classify_trust("something else entirely"), "untrusted")
        self.assertEqual(tls.classify_trust(None), "untrusted")

    def test_every_reason_has_an_explanation(self):
        for reason, explanation in tls.TRUST_EXPLANATIONS.items():
            with self.subTest(reason=reason):
                self.assertTrue(explanation.strip())


class TestPolicyFailed(unittest.TestCase):
    def _report(self, **summary):
        base = {"trusted": True, "days_remaining": 100, "issues": 0,
                "expires_within_threshold": False}
        base.update(summary)
        return {"summary": base}

    def test_a_healthy_certificate_passes(self):
        self.assertFalse(tls.policy_failed(self._report()))

    def test_untrusted_fails(self):
        self.assertTrue(tls.policy_failed(self._report(trusted=False)))

    def test_expired_fails(self):
        self.assertTrue(tls.policy_failed(self._report(days_remaining=-1)))

    def test_expiry_threshold_fails(self):
        self.assertTrue(tls.policy_failed(self._report(expires_within_threshold=True)))

    def test_weaknesses_only_fail_in_strict_mode(self):
        report = self._report(issues=3)
        self.assertFalse(tls.policy_failed(report))
        self.assertTrue(tls.policy_failed(report, strict=True))

    def test_a_report_without_a_verdict_fails_closed(self):
        """No evidence of a trusted certificate must not pass a security gate."""
        self.assertTrue(tls.policy_failed({}))


class TestContexts(unittest.TestCase):
    def test_verifying_context_checks_the_chain(self):
        context = tls.make_context(verifying=True)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def test_probe_context_deliberately_does_not_verify(self):
        """The whole point is to describe a certificate that failed to verify."""
        context = tls.make_context()
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        self.assertFalse(context.check_hostname)

    def test_protocol_pinning(self):
        context = tls.make_context(min_version=ssl.TLSVersion.TLSv1_2,
                                   max_version=ssl.TLSVersion.TLSv1_2)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(context.maximum_version, ssl.TLSVersion.TLSv1_2)


class TestProbeProtocolOffline(unittest.TestCase):
    def test_unknown_protocol_is_a_client_limitation(self):
        result = tls.probe_protocol("127.0.0.1", 1, "SSLv3", timeout=0.2)
        self.assertFalse(result["supported"])
        self.assertTrue(result["client_disabled"])

    def test_probe_protocols_covers_the_whole_list(self):
        results = tls.probe_protocols("127.0.0.1", 1, timeout=0.2)
        self.assertEqual([entry["protocol"] for entry in results],
                         [name for name, _ in tls.PROTOCOLS])
        for entry in results:
            self.assertFalse(entry["supported"])
            self.assertIn("error", entry)


class TestAuditOffline(unittest.TestCase):
    """Port 1 on loopback is closed, so the audit must report, not raise."""

    def _audit(self):
        return tls.audit("127.0.0.1:1", timeout=1.0, check_protocols=False)

    def test_report_shape(self):
        report = self._audit()
        self.assertEqual(report["kind"], "tls_audit")
        for key in ("target", "findings", "summary", "errors", "meta"):
            self.assertIn(key, report)
        self.assertEqual(report["meta"]["port"], 1)

    def test_unreachable_host_becomes_an_error(self):
        report = self._audit()
        self.assertTrue(report["errors"])
        self.assertIn("handshake", report["errors"][0].lower())
        self.assertFalse(report["findings"])

    def test_policy_fails_for_an_unreachable_host(self):
        self.assertTrue(tls.policy_failed(self._audit()))

    def test_present_does_not_crash_on_a_failure(self):
        report = self._audit()
        self.assertIs(tls.present(report), report)


class TestPresent(unittest.TestCase):
    def _report(self):
        return {
            "kind": "tls_audit", "target": "example.com",
            "meta": {"port": 443, "trust_explanation": "verified"},
            "summary": {"grade": "B", "trusted": True, "days_remaining": 20,
                        "expires_within_threshold": False},
            "findings": [
                {"item": "trust", "value": "trusted", "detail": "", "severity": ""},
                {"item": "days-remaining", "value": 20, "detail": "", "severity": ""},
                {"item": "protocol:TLSv1.2", "value": "supported",
                 "detail": "ECDHE-RSA-AES256-GCM-SHA384", "severity": ""},
                {"item": "protocol:TLSv1", "value": "supported",
                 "detail": "AES256-SHA", "severity": ""},
                {"item": "weakness:legacy-protocol-enabled", "value": "high",
                 "detail": "TLSv1 is deprecated", "severity": "high"},
            ],
            "errors": [],
        }

    def test_present_is_a_passthrough_when_quiet(self):
        report = self._report()
        self.assertIs(tls.present(report), report)

    def test_empty_summary_with_errors_does_not_crash(self):
        report = {"kind": "tls_audit", "target": "x", "meta": {}, "summary": {},
                  "findings": [], "errors": ["nope"]}
        self.assertIs(tls.present(report), report)


# --------------------------------------------------------------------------
# WIRING
# --------------------------------------------------------------------------


class TestTlsWiring(unittest.TestCase):
    def test_package_exports_the_tls_api(self):
        from modules import network

        for name in ("tls_report", "tls_audit", "present_tls", "policy_failed"):
            with self.subTest(name=name):
                self.assertTrue(hasattr(network, name))
                self.assertIn(name, network.__all__)

    def test_cli_has_a_working_handler(self):
        import cli

        self.assertIn("tls", cli.HANDLERS)
        self.assertEqual(cli.HISTORY_ACTIONS["tls"], "tls_audit")

    def test_cli_parses_the_audit_flags(self):
        import cli

        args = cli.build_parser().parse_args(
            ["tls", "example.com:8443", "--port", "9443", "--strict",
             "--expiry-days", "14", "--no-protocols"]
        )
        self.assertEqual(args.target, "example.com:8443")
        self.assertEqual(args.port, 9443)
        self.assertEqual(args.expiry_days, 14)
        self.assertTrue(args.strict)
        self.assertTrue(args.no_protocols)

    def test_tls_without_a_target_is_a_usage_error(self):
        import cli

        args = cli.build_parser().parse_args(["tls"])
        self.assertEqual(cli.cmd_tls(args), cli.EXIT_USAGE)

    def test_menu_exposes_the_audit(self):
        import main

        _, display = main._numbered(main.build_registry())
        labels = [label.lower() for _, items in display for _, label in items]
        self.assertTrue(any("tls" in label for label in labels),
                        "no menu entry mentions TLS")


if __name__ == "__main__":
    unittest.main()
