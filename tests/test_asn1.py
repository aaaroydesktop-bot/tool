"""
Tests for the dependency-free DER/X.509 reader in :mod:`core.asn1`.

Two real certificates are used as fixtures (base64 in ``tests/fixtures/``):

* a self-signed RSA-2048 certificate with DNS + IP SANs, ``CA:FALSE``,
  ``keyUsage`` and ``extendedKeyUsage=serverAuth``
* the public leaf certificate ``github.com`` served when this was written

The second one matters because it exercises the paths a self-signed certificate
cannot: an EC key on a named curve, a real issuer, OCSP / CA-issuer endpoints
and an SCT extension.

Every expected value below was cross-checked against ``openssl x509`` so these
tests lock in openssl's answer rather than the parser's own output.
"""

from __future__ import annotations

import base64
import datetime
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import asn1  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def fixture(name: str) -> bytes:
    """Decode one base64 certificate fixture into raw DER."""
    with open(os.path.join(FIXTURES, name), "r", encoding="ascii") as handle:
        return base64.b64decode(handle.read())


def self_signed_der() -> bytes:
    return fixture("self_signed_rsa2048.der.b64")


def public_leaf_der() -> bytes:
    return fixture("public_leaf_ec.der.b64")


# --------------------------------------------------------------------------
# TLV PRIMITIVES
# --------------------------------------------------------------------------


class TestReadTlv(unittest.TestCase):
    def test_short_form_length(self):
        # SEQUENCE { INTEGER 5 }
        tag, offset, length = asn1.read_tlv(b"\x30\x03\x02\x01\x05", 0)
        self.assertEqual((tag, offset, length), (0x30, 2, 3))

    def test_long_form_length(self):
        payload = b"\x04" + b"\x00" * 200
        blob = b"\x30\x81\xc8" + payload
        tag, offset, length = asn1.read_tlv(blob, 0)
        self.assertEqual((tag, offset, length), (0x30, 3, 200))

    def test_truncated_header_and_value(self):
        for blob in (b"", b"\x30", b"\x30\x05\x02\x01", b"\x30\x81"):
            with self.subTest(blob=blob):
                with self.assertRaises(asn1.DerError):
                    asn1.read_tlv(blob, 0)

    def test_indefinite_length_is_rejected(self):
        with self.assertRaises(asn1.DerError):
            asn1.read_tlv(b"\x30\x80\x00\x00", 0)

    def test_negative_offset(self):
        with self.assertRaises(asn1.DerError):
            asn1.read_tlv(b"\x30\x00", -1)


class TestChildren(unittest.TestCase):
    def test_iterates_every_child(self):
        # SEQUENCE { INTEGER 1, INTEGER 2 }
        blob = b"\x30\x06\x02\x01\x01\x02\x01\x02"
        _, offset, length = asn1.read_tlv(blob, 0)
        kids = list(asn1.children(blob, offset, length))
        self.assertEqual(len(kids), 2)
        self.assertEqual(asn1.read_der_integer(blob, kids[0][1], kids[0][2]), 1)
        self.assertEqual(asn1.read_der_integer(blob, kids[1][1], kids[1][2]), 2)

    def test_a_child_that_overruns_is_an_error(self):
        blob = b"\x30\x02\x02\x05\x00"
        _, offset, length = asn1.read_tlv(blob, 0)
        with self.assertRaises(asn1.DerError):
            list(asn1.children(blob, offset, length))


class TestOidDecoding(unittest.TestCase):
    def test_sha256_with_rsa(self):
        encoded = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B])
        self.assertEqual(asn1.oid_to_string(encoded), "1.2.840.113549.1.1.11")

    def test_two_arc_common_name(self):
        self.assertEqual(asn1.oid_to_string(bytes([0x55, 0x04, 0x03])), "2.5.4.3")

    def test_first_arc_saturates_at_two(self):
        # 0x88 0x37 0x01 -> first subidentifier 1079, so head is capped at 2.
        self.assertTrue(asn1.oid_to_string(bytes([0x88, 0x37, 0x01])).startswith("2."))

    def test_empty_is_an_error(self):
        with self.assertRaises(asn1.DerError):
            asn1.oid_to_string(b"")


class TestIntegerAndSerial(unittest.TestCase):
    def test_positive_and_negative(self):
        self.assertEqual(asn1.read_der_integer(b"\x00\x80", 0, 2), 128)
        self.assertEqual(asn1.read_der_integer(b"\x80", 0, 1), -128)

    def test_empty_integer_is_an_error(self):
        with self.assertRaises(asn1.DerError):
            asn1.read_der_integer(b"", 0, 0)

    def test_serial_keeps_the_leading_nibble(self):
        """Formatting the serial as an integer would eat a leading zero byte."""
        self.assertEqual(asn1.format_serial(b"\x00\xab"), "AB")
        self.assertEqual(asn1.format_serial(b"\xab"), "AB")
        self.assertEqual(asn1.format_serial(b"\x00\x0a"), "0A")

    def test_serial_of_zero(self):
        self.assertEqual(asn1.format_serial(b"\x00"), "00")


class TestFingerprint(unittest.TestCase):
    def test_shape_is_openssl_colon_hex(self):
        value = asn1.fingerprint(b"hello")
        self.assertEqual(len(value), 95)
        blocks = value.split(":")
        self.assertEqual(len(blocks), 32)
        for block in blocks:
            self.assertEqual(len(block), 2)
            self.assertEqual(block, block.upper())
            int(block, 16)

    def test_is_sha256_of_the_der(self):
        import hashlib

        der = self_signed_der()
        expected = hashlib.sha256(der).hexdigest().upper()
        self.assertEqual(asn1.fingerprint(der).replace(":", ""), expected)


class TestTimeParsing(unittest.TestCase):
    def test_utc_time(self):
        parsed = asn1.parse_time(asn1.UTC_TIME, b"260928140530Z")
        self.assertEqual(parsed,
                         datetime.datetime(2026, 9, 28, 14, 5, 30,
                                           tzinfo=datetime.timezone.utc))

    def test_generalized_time(self):
        parsed = asn1.parse_time(asn1.GENERALIZED_TIME, b"20360925140530Z")
        self.assertEqual(parsed,
                         datetime.datetime(2036, 9, 25, 14, 5, 30,
                                           tzinfo=datetime.timezone.utc))

    def test_malformed_is_an_error(self):
        with self.assertRaises(asn1.DerError):
            asn1.parse_time(asn1.UTC_TIME, b"nope")


# --------------------------------------------------------------------------
# CERTIFICATES
# --------------------------------------------------------------------------


class TestSelfSignedCertificate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fields = asn1.parse_certificate(self_signed_der())

    def test_identity_matches_the_subject(self):
        self.assertEqual(self.fields["subject_text"],
                         "CN=test.example.com, O=NetScan Test Org, C=US")
        self.assertEqual(self.fields["issuer_text"], self.fields["subject_text"])
        self.assertTrue(self.fields["self_signed"])

    def test_version(self):
        self.assertEqual(self.fields["version"], 3)

    def test_serial_matches_openssl(self):
        self.assertEqual(self.fields["serial"], "72FBBFDA8C92AD1B35029760310975A8A4F82957")

    def test_validity_window(self):
        self.assertEqual(self.fields["not_before"],
                         datetime.datetime(2026, 9, 28, 14, 5, 30,
                                           tzinfo=datetime.timezone.utc))
        self.assertEqual(self.fields["not_after"],
                         datetime.datetime(2036, 9, 25, 14, 5, 30,
                                           tzinfo=datetime.timezone.utc))

    def test_subject_alt_names_split_into_dns_and_ip(self):
        self.assertEqual(self.fields["dns_sans"],
                         ["test.example.com", "www.test.example.com"])
        self.assertEqual(self.fields["ip_sans"], ["192.0.2.10"])
        self.assertEqual(self.fields["sans"],
                         ["test.example.com", "www.test.example.com", "192.0.2.10"])

    def test_it_is_not_a_ca_and_is_for_server_auth(self):
        self.assertFalse(self.fields["is_ca"])
        self.assertTrue(self.fields["server_auth"])

    def test_key_usage_bits(self):
        self.assertEqual(self.fields["key_usage"],
                         ["digitalSignature", "keyEncipherment"])

    def test_rsa_key_size(self):
        key = self.fields["public_key"]
        self.assertEqual(key["algorithm"], "RSA")
        self.assertEqual(key["bits"], 2048)
        self.assertEqual(key["size"], "RSA 2048")

    def test_signature_algorithm_is_not_flagged_weak(self):
        self.assertEqual(self.fields["signature_algorithm"], "sha256WithRSA")
        self.assertFalse(self.fields["weak_signature"])

    def test_absent_extensions_stay_empty(self):
        self.assertEqual(self.fields["ocsp"], [])
        self.assertEqual(self.fields["ca_issuers"], [])
        self.assertFalse(self.fields["has_sct"])


class TestPublicLeafCertificate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fields = asn1.parse_certificate(public_leaf_der())

    def test_issuer_differs_from_subject(self):
        self.assertEqual(self.fields["subject_text"], "CN=github.com")
        self.assertIn("Sectigo", self.fields["issuer_text"])
        self.assertFalse(self.fields["self_signed"])

    def test_ec_key_on_a_named_curve(self):
        key = self.fields["public_key"]
        self.assertEqual(key["algorithm"], "EC")
        self.assertEqual(key["curve"], "P-256")
        self.assertEqual(key["bits"], 256)
        self.assertEqual(key["size"], "EC P-256")

    def test_signature_algorithm(self):
        self.assertEqual(self.fields["signature_algorithm"], "ecdsa-with-SHA256")
        self.assertFalse(self.fields["weak_signature"])

    def test_sans(self):
        self.assertEqual(self.fields["dns_sans"], ["github.com", "www.github.com"])
        self.assertEqual(self.fields["ip_sans"], [])

    def test_authority_information_access_is_decoded(self):
        """location is a single GeneralName, not a GeneralNames SEQUENCE."""
        self.assertEqual(self.fields["ocsp"], ["http://ocsp.sectigo.com"])
        self.assertTrue(self.fields["ca_issuers"][0].endswith(
            "SectigoPublicServerAuthenticationCADVE36.crt"))

    def test_certificate_transparency_extension(self):
        self.assertTrue(self.fields["has_sct"])

    def test_validity_is_parsed(self):
        self.assertEqual(self.fields["not_before"].year, 2026)


class TestParseCertificateRobustness(unittest.TestCase):
    def test_garbage_raises_dererror(self):
        for blob in (b"", b"not a certificate", b"\x02\x01\x05", b"\x30\x01"):
            with self.subTest(blob=blob):
                with self.assertRaises(asn1.DerError):
                    asn1.parse_certificate(blob)

    def test_truncated_certificate_raises(self):
        der = self_signed_der()
        with self.assertRaises(asn1.DerError):
            asn1.parse_certificate(der[:len(der) // 2])


# --------------------------------------------------------------------------
# NAME CLASSIFICATION HELPERS
# --------------------------------------------------------------------------


class TestNameClassification(unittest.TestCase):
    def test_ipv4(self):
        for value in ("192.0.2.10", "0.0.0.0", "255.255.255.255"):
            with self.subTest(value=value):
                self.assertTrue(asn1.is_ipv4(value))

    def test_not_ipv4(self):
        for value in ("example.com", "192.0.2", "192.0.2.256", "192.0.2.x"):
            with self.subTest(value=value):
                self.assertFalse(asn1.is_ipv4(value))

    def test_ipv6(self):
        self.assertTrue(asn1.is_ipv6("2001:db8::1"))
        self.assertFalse(asn1.is_ipv6("example.com"))

    def test_classify_names_splits_the_list(self):
        dns_names, addresses = asn1.classify_names(
            ["example.com", "192.0.2.1", "www.example.com", "2001:db8::1"]
        )
        self.assertEqual(dns_names, ["example.com", "www.example.com"])
        self.assertEqual(addresses, ["192.0.2.1", "2001:db8::1"])


if __name__ == "__main__":
    unittest.main()
