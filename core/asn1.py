"""
A minimal DER reader for X.509 certificates.

Why hand-roll this instead of reaching for a library?

* The toolkit's promise is that a bare Termux install works before ``pip`` has
  installed anything, so this stays on the standard library.
* More importantly, ``ssl.getpeercert()`` only returns parsed fields when the
  certificate *verified successfully*.  For an audit tool the interesting cases
  are exactly the ones that fail verification: self-signed, expired, wrong
  hostname, unknown issuer.  Those still need to be described in full.

Only the parts of X.509 this toolkit reports are implemented.  Anything
unexpected raises :class:`DerError` so callers can degrade gracefully instead of
showing wrong data.
"""

from __future__ import annotations

import datetime
import hashlib

__all__ = [
    "DerError",
    "children",
    "classify_names",
    "fingerprint",
    "format_serial",
    "is_ipv4",
    "is_ipv6",
    "oid_to_string",
    "parse_certificate",
    "parse_name",
    "parse_public_key_info",
    "parse_time",
    "read_der_integer",
    "read_tlv",
]


class DerError(ValueError):
    """The input was not the DER structure we expected."""


# --------------------------------------------------------------------------
# TAGS
# --------------------------------------------------------------------------

SEQUENCE = 0x30
SET = 0x31
INTEGER = 0x02
BIT_STRING = 0x03
OCTET_STRING = 0x04
OID = 0x06
BOOLEAN = 0x01
UTC_TIME = 0x17
GENERALIZED_TIME = 0x18

_STRING_TAGS = {
    0x0C: "utf-8",
    0x13: "ascii",   # PrintableString
    0x14: "ascii",   # T61String
    0x16: "ascii",   # IA5String
    0x1E: "utf-16-be",  # BMPString
}

# --------------------------------------------------------------------------
# OBJECT IDENTIFIERS
# --------------------------------------------------------------------------

OID_NAMES = {
    # attribute types
    "2.5.4.3": "CN",
    "2.5.4.4": "SN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "street",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.12": "title",
    "1.2.840.113549.1.9.1": "emailAddress",
    # signature algorithms
    "1.2.840.113549.1.1.4": "md5WithRSA (weak)",
    "1.2.840.113549.1.1.5": "sha1WithRSA (weak)",
    "1.2.840.113549.1.1.11": "sha256WithRSA",
    "1.2.840.113549.1.1.12": "sha384WithRSA",
    "1.2.840.113549.1.1.13": "sha512WithRSA",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1 (weak)",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "Ed25519",
    # public key algorithms
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10045.2.1": "EC",
    "1.3.101.112": "Ed25519",
    # named curves
    "1.2.840.10045.3.1.1": "P-192",
    "1.3.132.0.33": "P-224",
    "1.2.840.10045.3.1.7": "P-256",
    "1.3.132.0.34": "P-384",
    "1.3.132.0.35": "P-521",
    "1.3.132.0.10": "secp256k1",
}

CURVE_BITS = {
    "P-192": 192, "P-224": 224, "P-256": 256, "P-384": 384, "P-521": 521,
    "secp256k1": 256,
}

# extensions
EXT_SUBJECT_ALT_NAME = "2.5.29.17"
EXT_BASIC_CONSTRAINTS = "2.5.29.19"
EXT_KEY_USAGE = "2.5.29.15"
EXT_EXT_KEY_USAGE = "2.5.29.37"
EXT_AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1"
EXT_SCT = "1.3.6.1.4.1.11129.2.4.2"

EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
AIA_OCSP = "1.3.6.1.5.5.7.48.1"
AIA_CA_ISSUERS = "1.3.6.1.5.5.7.48.2"

OID_RSA = "1.2.840.113549.1.1.1"
OID_EC = "1.2.840.10045.2.1"
OID_ED25519 = "1.3.101.112"
OID_ED448 = "1.3.101.113"


# --------------------------------------------------------------------------
# TLV PRIMITIVES
# --------------------------------------------------------------------------


def read_tlv(data: bytes, offset: int = 0) -> tuple[int, int, int]:
    """
    Read one type-length-value at ``offset``.

    Returns ``(tag, value_offset, value_length)``.
    """
    if offset < 0 or offset + 2 > len(data):
        raise DerError("truncated TLV header")

    tag = data[offset]
    cursor = offset + 1
    first = data[cursor]
    cursor += 1

    if first & 0x80:
        count = first & 0x7F
        if count == 0:
            raise DerError("indefinite lengths are not valid DER")
        if count > 4:
            raise DerError("length field is implausibly large")
        if cursor + count > len(data):
            raise DerError("truncated length field")
        length = int.from_bytes(data[cursor:cursor + count], "big")
        cursor += count
    else:
        length = first

    if cursor + length > len(data):
        raise DerError("TLV value runs past the end of the buffer")

    return tag, cursor, length


def children(data: bytes, offset: int, length: int):
    """Yield ``(tag, value_offset, value_length)`` for each child of a container."""
    end = offset + length
    cursor = offset
    while cursor < end:
        tag, value_offset, value_length = read_tlv(data, cursor)
        yield tag, value_offset, value_length
        cursor = value_offset + value_length


def _value(data: bytes, offset: int, length: int) -> bytes:
    return data[offset:offset + length]


def _first_child(data: bytes, offset: int, length: int):
    for child in children(data, offset, length):
        return child
    raise DerError("container is empty")


def read_der_integer(data: bytes, offset: int, length: int) -> int:
    raw = _value(data, offset, length)
    if not raw:
        raise DerError("empty INTEGER")
    return int.from_bytes(raw, "big", signed=raw[0] & 0x80 != 0)


def oid_to_string(raw: bytes) -> str:
    """Decode a dotted OID from its DER value bytes."""
    numbers: list[int] = []
    accumulator = 0
    for byte in raw:
        accumulator = (accumulator << 7) | (byte & 0x7F)
        if not byte & 0x80:
            numbers.append(accumulator)
            accumulator = 0
    if not numbers:
        raise DerError("empty OID")

    first = numbers[0]
    # The first octet packs the first two arcs as 40*a + b, capped at 2 for a.
    head = min(first // 40, 2)
    return ".".join([str(head), str(first - 40 * head)] + [str(n) for n in numbers[1:]])


def _decode_string(tag: int, raw: bytes) -> str:
    encoding = _STRING_TAGS.get(tag)
    if encoding is None:
        return raw.decode("utf-8", errors="replace")
    return raw.decode(encoding, errors="replace")


def parse_time(tag: int, raw: bytes) -> datetime.datetime:
    """Parse UTCTime or GeneralizedTime into an aware UTC datetime."""
    text = raw.decode("ascii", errors="replace")
    digits = "".join(char for char in text if char.isdigit())
    if tag == UTC_TIME:
        if len(digits) < 12:
            raise DerError("malformed UTCTime")
        moment = datetime.datetime.strptime(digits[:12], "%y%m%d%H%M%S")
    else:
        if len(digits) < 14:
            raise DerError("malformed GeneralizedTime")
        moment = datetime.datetime.strptime(digits[:14], "%Y%m%d%H%M%S")
    return moment.replace(tzinfo=datetime.timezone.utc)


# --------------------------------------------------------------------------
# NAMES
# --------------------------------------------------------------------------


def parse_name(data: bytes, offset: int, length: int) -> dict[str, str]:
    """Flatten an X.509 Name (RDNSequence) into ``{"CN": ..., "O": ...}``."""
    result: dict[str, str] = {}

    for _, set_offset, set_length in children(data, offset, length):
        for _, pair_offset, pair_length in children(data, set_offset, set_length):
            try:
                parts = list(children(data, pair_offset, pair_length))
            except DerError:
                continue
            if len(parts) < 2:
                continue
            _, oid_offset, oid_length = parts[0]
            if parts[0][0] != OID:
                continue
            name = OID_NAMES.get(oid_to_string(_value(data, oid_offset, oid_length)))
            if not name:
                continue
            tag, value_offset, value_length = parts[1]
            text = _decode_string(tag, _value(data, value_offset, value_length)).strip()
            if text and name not in result:
                result[name] = text

    return result


def _name_oneline(name: dict[str, str]) -> str:
    order = ("CN", "O", "OU", "L", "ST", "C", "emailAddress")
    parts = [f"{key}={name[key]}" for key in order if key in name]
    parts += [f"{k}={v}" for k, v in name.items() if k not in order]
    return ", ".join(parts)


# --------------------------------------------------------------------------
# PUBLIC KEY
# --------------------------------------------------------------------------


def parse_public_key_info(data: bytes, offset: int, length: int) -> dict:
    """Describe the subject public key: algorithm, size and curve."""
    parts = list(children(data, offset, length))
    if len(parts) < 2:
        raise DerError("SubjectPublicKeyInfo needs an algorithm and a key")

    alg_tag, alg_offset, alg_length = parts[0]
    if alg_tag != SEQUENCE:
        raise DerError("algorithm identifier is not a SEQUENCE")

    alg_parts = list(children(data, alg_offset, alg_length))
    if not alg_parts or alg_parts[0][0] != OID:
        raise DerError("algorithm identifier has no OID")
    _, oid_offset, oid_length = alg_parts[0]
    algorithm = oid_to_string(_value(data, oid_offset, oid_length))

    curve = None
    if len(alg_parts) > 1 and alg_parts[1][0] == OID:
        _, curve_offset, curve_length = alg_parts[1]
        curve = oid_to_string(_value(data, curve_offset, curve_length))

    key_tag, key_offset, key_length = parts[1]
    if key_tag != BIT_STRING:
        raise DerError("subjectPublicKey is not a BIT STRING")
    key_bits = _value(data, key_offset, key_length)
    if not key_bits:
        raise DerError("empty BIT STRING")
    # First octet is the count of unused trailing bits; drop it.
    key_bits = key_bits[1:]

    result = {
        "algorithm": OID_NAMES.get(algorithm, algorithm),
        "oid": algorithm,
        "bits": None,
        "curve": None,
        "size": None,
    }

    if algorithm == OID_RSA:
        # RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        _, rsa_offset, rsa_length = _first_child_tlv(key_bits, 0)
        inner = list(children(key_bits, rsa_offset, rsa_length))
        if not inner:
            raise DerError("RSAPublicKey is empty")
        _, modulus_offset, modulus_length = inner[0]
        modulus = read_der_integer(key_bits, modulus_offset, modulus_length)
        # Round up to a whole number of bytes: a 2048-bit key is 2048, not 2047.
        bits = ((modulus.bit_length() + 7) // 8) * 8
        result.update(bits=bits, size=f"RSA {bits}")
    elif algorithm == OID_EC:
        label = OID_NAMES.get(curve or "", curve)
        # A compressed point is 1 + ceil(bits/8); an uncompressed point is
        # 1 + 2*ceil(bits/8). Derive the field size from the point length.
        points = max(len(key_bits) - 1, 0)
        bits = CURVE_BITS.get(label or "") or (points // 2) * 8 or None
        result.update(bits=bits, curve=label, size=f"EC {label}" if label else "EC")
    elif algorithm in (OID_ED25519, OID_ED448):
        bits = 256 if algorithm == OID_ED25519 else 456
        result.update(bits=bits, size=f"{OID_NAMES[algorithm]} ({bits}-bit)")
    else:
        result.update(size=OID_NAMES.get(algorithm, algorithm))

    return result


def _first_child_tlv(data: bytes, offset: int):
    """``read_tlv`` for the TLV starting exactly at ``offset``."""
    return read_tlv(data, offset)


# --------------------------------------------------------------------------
# EXTENSIONS
# --------------------------------------------------------------------------


def _general_name(data: bytes, tag: int, offset: int, length: int) -> str | None:
    """Decode one GeneralName, or ``None`` when it is a kind we ignore."""
    raw = _value(data, offset, length)
    if not raw:
        return None
    if tag in (0x82, 0x81, 0x86):            # dNSName, rfc822Name, URI
        return raw.decode("ascii", errors="replace")
    if tag == 0x87 and len(raw) == 4:        # iPAddress (IPv4)
        return ".".join(str(byte) for byte in raw)
    if tag == 0x87 and len(raw) == 16:       # iPAddress (IPv6)
        return ":".join(raw[i:i + 2].hex() for i in range(0, 16, 2))
    return None


def _general_names(data: bytes, offset: int, length: int) -> list[str]:
    """Extract values from a GeneralNames SEQUENCE (SEQUENCE OF GeneralName)."""
    values: list[str] = []
    for tag, item_offset, item_length in children(data, offset, length):
        value = _general_name(data, tag, item_offset, item_length)
        if value:
            values.append(value)
    return values


def _parse_extensions(data: bytes, offset: int, length: int) -> dict:
    """Read the extension blocks this toolkit reports on."""
    found = {
        "sans": [], "dns_names": [], "ip_addresses": [], "is_ca": False,
        "has_sct": False, "server_auth": None, "ocsp": [], "ca_issuers": [],
        "key_usage": [],
    }

    wrapper = list(children(data, offset, length))
    if not wrapper:
        return found
    _, seq_offset, seq_length = wrapper[0]

    for _, ext_offset, ext_length in children(data, seq_offset, seq_length):
        parts = list(children(data, ext_offset, ext_length))
        if len(parts) < 2 or parts[0][0] != OID:
            continue
        _, oid_offset, oid_length = parts[0]
        ext_oid = oid_to_string(_value(data, oid_offset, oid_length))
        value_tag, value_offset, value_length = parts[-1]
        if value_tag != OCTET_STRING:
            continue
        payload = _value(data, value_offset, value_length)

        try:
            if ext_oid == EXT_SUBJECT_ALT_NAME:
                _, san_offset, san_length = _first_child(payload, 0, len(payload))
                names = _general_names(payload, san_offset, san_length)
                dns_names, addresses = classify_names(names)
                found["sans"] = names
                found["dns_names"] = dns_names
                found["ip_addresses"] = addresses
            elif ext_oid == EXT_BASIC_CONSTRAINTS:
                inside = list(children(payload, 0, len(payload)))
                if inside and inside[0][0] == SEQUENCE:
                    inner = list(children(payload, inside[0][1], inside[0][2]))
                    if inner and inner[0][0] == BOOLEAN:
                        found["is_ca"] = payload[inner[0][1]] != 0
            elif ext_oid == EXT_EXT_KEY_USAGE:
                inside = list(children(payload, 0, len(payload)))
                if inside:
                    for _, eku_offset, eku_length in children(payload, inside[0][1],
                                                              inside[0][2]):
                        purp = oid_to_string(_value(payload, eku_offset, eku_length))
                        if purp == EKU_SERVER_AUTH:
                            found["server_auth"] = True
            elif ext_oid == EXT_KEY_USAGE:
                inside = list(children(payload, 0, len(payload)))
                if inside and inside[0][0] == BIT_STRING:
                    found["key_usage"] = _key_usage_bits(
                        _value(payload, inside[0][1], inside[0][2]))
            elif ext_oid == EXT_AUTHORITY_INFO_ACCESS:
                inside = list(children(payload, 0, len(payload)))
                if inside:
                    for _, desc_offset, desc_length in children(payload, inside[0][1],
                                                                inside[0][2]):
                        desc = list(children(payload, desc_offset, desc_length))
                        if len(desc) < 2 or desc[0][0] != OID:
                            continue
                        method = oid_to_string(_value(payload, desc[0][1], desc[0][2]))
                        # AccessDescription.location is a single GeneralName,
                        # not a GeneralNames SEQUENCE.
                        location = _general_name(payload, desc[1][0], desc[1][1], desc[1][2])
                        if location and method == AIA_OCSP:
                            found["ocsp"].append(location)
                        elif location and method == AIA_CA_ISSUERS:
                            found["ca_issuers"].append(location)
            elif ext_oid == EXT_SCT:
                found["has_sct"] = True
        except DerError:
            continue

    return found


def is_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255
                                   for part in parts)


def is_ipv6(value: str) -> bool:
    return ":" in value


def classify_names(names) -> tuple[list[str], list[str]]:
    """Split SAN entries into ``(dns_names, ip_addresses)``."""
    dns_names: list[str] = []
    addresses: list[str] = []
    for name in names:
        (addresses if is_ipv4(name) or is_ipv6(name) else dns_names).append(name)
    return dns_names, addresses


_KEY_USAGE_BITS = ("digitalSignature", "nonRepudiation", "keyEncipherment",
                   "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign",
                   "encipherOnly", "decipherOnly")


def _key_usage_bits(raw: bytes) -> list[str]:
    if not raw:
        return []
    unused = raw[0]
    bits = "".join(f"{byte:08b}" for byte in raw[1:]) or ""
    bits = bits[:len(bits) - unused] if unused <= len(bits) else bits
    return [name for index, name in enumerate(_KEY_USAGE_BITS)
            if index < len(bits) and bits[index] == "1"]


# --------------------------------------------------------------------------
# CERTIFICATE
# --------------------------------------------------------------------------


def format_serial(raw: bytes) -> str:
    """
    Render a serial number the way openssl does: uppercase hex, keeping any
    leading zero nibble (which formatting it as an integer would eat).
    """
    if len(raw) > 1 and raw[0] == 0x00:  # DER sign padding on a positive serial
        raw = raw[1:]
    return raw.hex().upper() or "00"


def fingerprint(der: bytes) -> str:
    """Colon-separated uppercase SHA-256 fingerprint, as openssl prints it."""
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def parse_certificate(der: bytes) -> dict:
    """
    Parse a DER certificate into the fields the audit reports.

    Raises :class:`DerError` on anything unexpected, so callers can fall back to
    the coarse information from ``ssl.getpeercert()``.
    """
    tag, offset, length = read_tlv(der, 0)
    if tag != SEQUENCE:
        raise DerError("certificate is not a SEQUENCE")

    top = list(children(der, offset, length))
    if len(top) < 3:
        raise DerError("certificate must have three parts")

    tbs_tag, tbs_offset, tbs_length = top[0]
    if tbs_tag != SEQUENCE:
        raise DerError("tbsCertificate is not a SEQUENCE")

    sig_tag, sig_offset, sig_length = top[1]
    signature_algorithm = None
    if sig_tag == SEQUENCE:
        oid_tag, oid_offset, oid_length = _first_child(der, sig_offset, sig_length)
        if oid_tag == OID:
            signature_algorithm = oid_to_string(_value(der, oid_offset, oid_length))

    fields = list(children(der, tbs_offset, tbs_length))
    cursor = 0

    version = 1
    if fields and fields[0][0] == 0xA0:  # [0] EXPLICIT version
        inner = list(children(der, fields[0][1], fields[0][2]))
        if inner:
            version = read_der_integer(der, inner[0][1], inner[0][2]) + 1
        cursor = 1

    if len(fields) < cursor + 6:
        raise DerError("tbsCertificate is missing mandatory fields")

    serial = format_serial(_value(der, fields[cursor][1], fields[cursor][2]))
    cursor += 1
    cursor += 1  # signature AlgorithmIdentifier (duplicated inside tbs)

    issuer = parse_name(der, fields[cursor][1], fields[cursor][2])
    cursor += 1

    validity = list(children(der, fields[cursor][1], fields[cursor][2]))
    if len(validity) < 2:
        raise DerError("validity has fewer than two timestamps")
    not_before = parse_time(validity[0][0], _value(der, validity[0][1], validity[0][2]))
    not_after = parse_time(validity[1][0], _value(der, validity[1][1], validity[1][2]))
    cursor += 1

    subject = parse_name(der, fields[cursor][1], fields[cursor][2])
    cursor += 1

    public_key = parse_public_key_info(der, fields[cursor][1], fields[cursor][2])
    cursor += 1

    extensions = {
        "sans": [], "dns_names": [], "ip_addresses": [], "is_ca": False,
        "has_sct": False, "server_auth": None, "ocsp": [], "ca_issuers": [],
        "key_usage": [],
    }
    for remaining in fields[cursor:]:
        if remaining[0] == 0xA3:  # [3] EXPLICIT extensions
            extensions = _parse_extensions(der, remaining[1], remaining[2])
            break

    return {
        "version": version,
        "serial": serial,
        "signature_algorithm": OID_NAMES.get(signature_algorithm or "",
                                             signature_algorithm or "unknown"),
        "signature_oid": signature_algorithm,
        "weak_signature": "weak" in OID_NAMES.get(signature_algorithm or "", ""),
        "subject": subject,
        "subject_text": _name_oneline(subject),
        "issuer": issuer,
        "issuer_text": _name_oneline(issuer),
        "not_before": not_before,
        "not_after": not_after,
        "public_key": public_key,
        "sans": extensions["sans"],
        "dns_sans": extensions["dns_names"],
        "ip_sans": extensions["ip_addresses"],
        "is_ca": extensions["is_ca"],
        "has_sct": extensions["has_sct"],
        "server_auth": extensions["server_auth"],
        "key_usage": extensions["key_usage"],
        "ocsp": extensions["ocsp"],
        "ca_issuers": extensions["ca_issuers"],
        "self_signed": bool(subject) and subject == issuer,
        "fingerprint": fingerprint(der),
        "der_size": len(der),
    }
