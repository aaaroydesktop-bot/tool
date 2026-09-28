"""
Deep TLS / certificate audit.

Everything here is standard library only: ``ssl`` for the handshake and
:mod:`core.asn1` for the certificate.  That means it runs on a bare Termux
install *and* can describe certificates that fail verification, which is where
the interesting findings live.

What it reports:

* trust outcome (trusted / self-signed / expired / hostname mismatch / unknown
  issuer) from a real verifying handshake, with the exact reason
* full certificate detail: subject, issuer, serial, validity window with a
  countdown, SAN list (a free source of extra hostnames), key type and size,
  signature algorithm, OCSP/CA-issuer endpoints, CT log presence
* which protocol versions the server still accepts and the cipher negotiated
  for each, flagging legacy SSL/TLS 1.0/1.1 and weak suites
* forward-secrecy posture
* a letter grade, so a result can be read at a glance

Every finding uses the same four keys (``item``/``value``/``detail``/
``severity``) so the JSON, Markdown, HTML and CSV renderers all produce tidy
tables for it.
"""

from __future__ import annotations

import datetime
import socket
import ssl

from rich.panel import Panel
from rich.table import Table

from core import asn1
from core import report as reportlib
from core.console import console, err, info, is_quiet, warn
from core.netutil import parse_target

DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 8.0
DEFAULT_ALPN = ("h2", "http/1.1")

#: Protocol versions probed, newest first so the report reads naturally.
PROTOCOLS = (
    ("TLSv1.3", "TLSv1_3"),
    ("TLSv1.2", "TLSv1_2"),
    ("TLSv1.1", "TLSv1_1"),
    ("TLSv1", "TLSv1"),
)

LEGACY_PROTOCOLS = {"TLSv1", "TLSv1.1"}

#: Substrings that mark a cipher suite as unfit for modern use.
WEAK_CIPHER_MARKERS = {
    "RC4": "RC4 is broken",
    "3DES": "3DES is deprecated (SWEET32)",
    "MD5": "MD5 integrity",
    "NULL": "no encryption",
    "EXPORT": "export-grade strength",
    "ANON": "anonymous key exchange",
    "_DES_": "single DES",
    "DES40": "single DES",
    "IDEA": "obsolete cipher",
    "SEED": "obsolete cipher",
    "CAMELLIA": "not in modern preference lists",
}

#: Static RSA key exchange: no forward secrecy.
STATIC_RSA_MARKERS = ("TLS_RSA_WITH_", "TLS_RSA_PSK_")

GRADE_LADDER = ("A+", "A", "A-", "B+", "B", "B-", "C+", "C", "C-", "D", "E", "F")

TRUST_EXPLANATIONS = {
    "trusted": "chain verified against the system trust store, hostname matches",
    "self-signed": "the certificate signs itself; nothing attests to its identity",
    "unknown-issuer": "the issuing CA is not in the trust store (private or rogue CA)",
    "expired": "the certificate is past its notAfter date",
    "not-yet-valid": "the certificate's notBefore date is in the future",
    "hostname-mismatch": "the certificate is valid but was not issued for this host",
    "untrusted": "verification failed",
}


# --------------------------------------------------------------------------
# PURE HELPERS
# --------------------------------------------------------------------------


def protocol_enum(name: str):
    """Resolve ``"TLSv1.2"`` to the ``ssl.TLSVersion`` member, if available."""
    attribute = dict(PROTOCOLS).get(name)
    if not attribute:
        return None
    return getattr(ssl.TLSVersion, attribute, None)


def days_remaining(not_after: datetime.datetime,
                   now: datetime.datetime | None = None) -> int:
    """Whole days until expiry; negative once expired."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=datetime.timezone.utc)
    return int((not_after - now).total_seconds() // 86400)


def weak_cipher_reason(name: str | None) -> str | None:
    """Why a cipher suite is weak, or ``None`` when it is fine."""
    if not name:
        return None
    upper = name.upper()
    for marker, reason in WEAK_CIPHER_MARKERS.items():
        if marker in upper:
            return reason
    return None


def has_forward_secrecy(name: str | None) -> bool:
    """False only for suites that use static RSA key exchange."""
    if not name:
        return False
    upper = name.upper()
    if any(marker in upper for marker in STATIC_RSA_MARKERS):
        return False
    return ("ECDHE" in upper or "DHE" in upper
            or upper.startswith("TLS_AES") or upper.startswith("TLS_CHACHA"))


def grade(*, trusted: bool, days_left: int | None, legacy: bool, weak: bool,
          fs_missing: bool, key_bits: int | None, weak_signature: bool,
          self_signed: bool = False) -> str:
    """Reduce an audit to one letter, the way a report card would.

    ``key_bits`` is the RSA modulus size (pass ``None`` for EC/Ed25519 keys,
    which are not comparable on that scale).
    """
    if not trusted or (days_left is not None and days_left < 0):
        return "F"

    index = 0

    def demote(steps: int, floor: int | None = None) -> None:
        """Worse by ``steps``, but never better than ``floor``."""
        nonlocal index
        index += steps
        if floor is not None:
            index = max(index, floor)

    if self_signed:
        demote(1)
    if legacy:
        demote(1, GRADE_LADDER.index("B+"))
    if weak:
        demote(2)
    if fs_missing:
        demote(1, GRADE_LADDER.index("B-"))
    if weak_signature:
        demote(2, GRADE_LADDER.index("C"))
    if key_bits is not None and key_bits < 2048:
        demote(1)
    if days_left is not None:
        if days_left < 14:
            demote(2, GRADE_LADDER.index("C+"))
        elif days_left < 30:
            demote(1, GRADE_LADDER.index("B"))

    return GRADE_LADDER[min(index, len(GRADE_LADDER) - 1)]


def classify_trust(verify_message: str | None) -> str:
    """Turn an OpenSSL verify message into a stable, explainable reason."""
    text = (verify_message or "").lower()
    if "hostname mismatch" in text or "ip address mismatch" in text:
        return "hostname-mismatch"
    if "expired" in text:
        return "expired"
    if "not yet valid" in text:
        return "not-yet-valid"
    if "self-signed" in text or "self signed" in text:
        return "self-signed"
    if "unable to get local issuer" in text or "unable to get issuer" in text:
        return "unknown-issuer"
    return "untrusted"


# --------------------------------------------------------------------------
# PROBES
# --------------------------------------------------------------------------


def make_context(verifying: bool = False, alpn=DEFAULT_ALPN,
                 min_version=None, max_version=None):
    """Build the SSL context used for a probe."""
    context = ssl.create_default_context() if verifying else \
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verifying:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if alpn:
        try:
            context.set_alpn_protocols(list(alpn))
        except NotImplementedError:
            pass
    if min_version is not None:
        context.minimum_version = min_version
    if max_version is not None:
        context.maximum_version = max_version
    return context


def probe_protocol(host: str, port: int, name: str,
                   timeout: float = DEFAULT_TIMEOUT) -> dict:
    """
    Ask whether one protocol version completes a handshake.

    A version the *client* build refuses to speak is reported as
    ``client_disabled`` rather than pretending the server refused it.
    """
    result = {"protocol": name, "supported": False, "cipher": None, "bits": None,
              "error": None, "client_disabled": False}

    version = protocol_enum(name)
    if version is None:
        result.update(client_disabled=True, error="this build has no such version")
        return result

    try:
        context = make_context(min_version=version, max_version=version)
    except (ValueError, OSError) as exc:
        result.update(client_disabled=True, error=f"client refuses it: {exc}"[:100])
        return result

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cipher = tls.cipher() or ("", "", 0)
                result.update(supported=True, cipher=cipher[0], bits=cipher[2])
    except ssl.SSLError as exc:
        message = str(exc)
        result["error"] = message[:100]
        lowered = message.lower()
        # "no ciphers available" is what OpenSSL 3.x reports when its own
        # security level has disabled a legacy version\: the *client* refused,
        # the server was never asked.
        if ("no protocols available" in lowered or "unsupported protocol" in lowered
                or "no ciphers available" in lowered):
            result["client_disabled"] = True
    except (OSError, ValueError) as exc:
        result["error"] = str(exc)[:100]

    return result


def probe_protocols(host: str, port: int, timeout: float = DEFAULT_TIMEOUT,
                    versions=None) -> list[dict]:
    names = versions or [name for name, _ in PROTOCOLS]
    return [probe_protocol(host, port, name, timeout=timeout) for name in names]


def probe_certificate(host: str, port: int = DEFAULT_PORT,
                      timeout: float = DEFAULT_TIMEOUT, alpn=DEFAULT_ALPN) -> dict:
    """
    Fetch and describe the served certificate, trusted or not.

    A verifying handshake decides *trust*; a second, unverified handshake grabs
    the DER so the certificate can still be described when verification fails.
    """
    result = {
        "trusted": None, "trust": "untrusted", "verify_error": None,
        "connection_error": None, "tls_version": None, "cipher": None,
        "alpn": None, "fields": {}, "parse_error": None, "fingerprint": None,
    }

    try:
        context = make_context(verifying=True, alpn=alpn)
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cipher = tls.cipher() or (None,)
                result.update(
                    trusted=True, trust="trusted", tls_version=tls.version(),
                    cipher=cipher[0], alpn=tls.selected_alpn_protocol(),
                )
    except ssl.SSLCertVerificationError as exc:
        message = getattr(exc, "verify_message", None) or str(exc)
        result.update(trusted=False, verify_error=message, trust=classify_trust(message))
    except (ssl.SSLError, OSError, ValueError) as exc:
        result["connection_error"] = str(exc)[:150]

    der = None
    try:
        context = make_context(alpn=alpn)
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                if result["tls_version"] is None:
                    result["tls_version"] = tls.version()
                if result["cipher"] is None:
                    result["cipher"] = (tls.cipher() or (None,))[0]
                if result["alpn"] is None:
                    result["alpn"] = tls.selected_alpn_protocol()
    except (ssl.SSLError, OSError, ValueError) as exc:
        if result["connection_error"] is None and result["trusted"] is not True:
            result["connection_error"] = str(exc)[:150]

    if der:
        result["fingerprint"] = asn1.fingerprint(der)
        try:
            fields = asn1.parse_certificate(der)
        except asn1.DerError as exc:
            result["parse_error"] = str(exc)
        else:
            result["fields"] = fields
            if not result["trusted"]:
                # Refine "untrusted" using something we can see ourselves.
                if fields["self_signed"]:
                    result["trust"] = "self-signed"

    return result


# --------------------------------------------------------------------------
# THE AUDIT
# --------------------------------------------------------------------------


def audit(target: str, port: int | None = None, timeout: float = DEFAULT_TIMEOUT,
          check_protocols: bool = True, expiry_days: int | None = None) -> dict:
    """Run the full audit and return a report dict."""
    host, parsed_port = parse_target(target)
    port = port or parsed_port or DEFAULT_PORT

    report = reportlib.new_report("tls_audit", host, port=port, timeout=timeout)
    info(f"Auditing TLS on {host}:{port}...")

    def fact(item: str, value, detail=None, severity=""):
        reportlib.add_finding(report, item=item, value=value, detail=detail or "",
                              severity=severity)

    def weakness(name: str, severity: str, detail: str):
        fact(f"weakness:{name}", severity, detail, severity)

    cert = probe_certificate(host, port, timeout=timeout)

    if cert.get("connection_error") and not cert.get("fields"):
        reportlib.add_error(report, "cannot complete a TLS handshake: "
                                    f"{cert['connection_error']}")
        reportlib.finish(report, reachable=False)
        return report

    fields = cert.get("fields") or {}
    trust = "trusted" if cert.get("trusted") else cert.get("trust", "untrusted")

    # ---- certificate facts ----------------------------------------------------
    fact("trust", trust, TRUST_EXPLANATIONS.get(trust))
    if cert.get("verify_error"):
        fact("verify-error", cert["verify_error"])
    if cert.get("parse_error"):
        fact("certificate", f"could not be parsed: {cert['parse_error']}")

    days_left = None
    if fields:
        days_left = days_remaining(fields["not_after"])
        fact("subject", fields["subject_text"])
        fact("issuer", fields["issuer_text"])
        fact("serial", fields["serial"])
        fact("valid-from", fields["not_before"].isoformat(timespec="seconds"))
        fact("valid-until", fields["not_after"].isoformat(timespec="seconds"))
        fact("days-remaining", days_left)
        fact("key", fields["public_key"]["size"])
        fact("signature-algorithm", fields["signature_algorithm"])
        fact("fingerprint-sha256", fields["fingerprint"])
        if fields["dns_sans"]:
            fact("san-dns", ", ".join(fields["dns_sans"]))
        if fields["ip_sans"]:
            fact("san-ip", ", ".join(fields["ip_sans"]))
        if fields["ocsp"]:
            fact("ocsp", ", ".join(fields["ocsp"]))
        if fields["ca_issuers"]:
            fact("ca-issuers", ", ".join(fields["ca_issuers"]))
        fact("certificate-transparency",
             "SCT present" if fields["has_sct"] else "none reported")
    elif cert.get("fingerprint"):
        fact("fingerprint-sha256", cert["fingerprint"])

    if cert.get("tls_version"):
        fact("negotiated", cert["tls_version"])
    if cert.get("cipher"):
        fact("negotiated-cipher", cert["cipher"])
    if cert.get("alpn"):
        fact("alpn", cert["alpn"])

    # ---- protocol matrix ------------------------------------------------------
    protocols = probe_protocols(host, port, timeout=timeout) if check_protocols else []
    for entry in protocols:
        detail = entry["cipher"] or entry["error"] or ""
        if entry["client_disabled"] and not entry["supported"]:
            detail = f"client build disabled it ({detail})" if detail else \
                "client build disabled it"
        fact(f"protocol:{entry['protocol']}",
             "supported" if entry["supported"] else "refused", detail)

    supported = [entry for entry in protocols if entry["supported"]]
    legacy_on = [entry["protocol"] for entry in supported
                 if entry["protocol"] in LEGACY_PROTOCOLS]
    weak_suites = [(entry["protocol"], weak_cipher_reason(entry["cipher"]))
                   for entry in supported if weak_cipher_reason(entry["cipher"])]
    no_fs = [entry["protocol"] for entry in supported
             if entry["cipher"] and not has_forward_secrecy(entry["cipher"])]

    # ---- weaknesses -----------------------------------------------------------
    if trust != "trusted":
        weakness("certificate-not-trusted", "high", TRUST_EXPLANATIONS.get(trust, trust))
    if days_left is not None:
        if days_left < 0:
            weakness("certificate-expired", "high", f"expired {-days_left} day(s) ago")
        elif days_left < 30:
            weakness("certificate-expiring-soon",
                     "medium" if days_left < 14 else "low",
                     f"{days_left} day(s) left")
    for name in legacy_on:
        weakness("legacy-protocol-enabled", "high",
                 f"{name} is deprecated (RFC 8996)")
    for protocol, reason in weak_suites:
        weakness("weak-cipher-suite", "high", f"{protocol}: {reason}")
    if no_fs:
        weakness("no-forward-secrecy", "medium",
                 f"static RSA key exchange on {', '.join(no_fs)}")
    if fields.get("weak_signature"):
        weakness("weak-signature-algorithm", "high", fields["signature_algorithm"])
    # The 2048-bit floor is an RSA rule; a 256-bit EC key is not "small".
    public_key = fields.get("public_key") or {}
    key_bits = public_key.get("bits")
    rsa_bits = key_bits if public_key.get("algorithm") == "RSA" else None
    if rsa_bits and rsa_bits < 2048:
        weakness("weak-key-size", "medium", f"{public_key['size']} is below 2048 bits")
    if fields and not fields["has_sct"]:
        weakness("no-certificate-transparency", "low", "no SCT extension")

    issues = [finding for finding in report["findings"]
              if str(finding["item"]).startswith("weakness:")]
    high = sum(1 for finding in issues if finding["severity"] == "high")

    report["meta"].update({
        "trust_explanation": TRUST_EXPLANATIONS.get(trust, trust),
        "protocols_supported": [entry["protocol"] for entry in supported],
        "alpn": cert.get("alpn"),
        "certificate": {
            "subject": fields.get("subject_text"),
            "issuer": fields.get("issuer_text"),
            "not_after": fields["not_after"].isoformat() if fields else None,
            "sans": fields.get("sans"),
        } if fields else {},
    })

    expired_within = (expiry_days is not None and days_left is not None
                      and days_left < expiry_days)

    reportlib.finish(
        report,
        grade=grade(
            trusted=bool(cert.get("trusted")),
            days_left=days_left,
            legacy=bool(legacy_on),
            weak=bool(weak_suites),
            fs_missing=bool(no_fs),
            key_bits=rsa_bits,
            weak_signature=bool(fields.get("weak_signature")),
            self_signed=bool(fields.get("self_signed")),
        ),
        trusted=bool(cert.get("trusted")),
        trust=trust,
        days_remaining=days_left,
        protocols=len(supported),
        legacy_protocols=", ".join(legacy_on) or None,
        issues=len(issues),
        high_severity=high,
        expires_within_threshold=expired_within,
    )
    return report


def policy_failed(report: dict, strict: bool = False) -> bool:
    """Whether the audit should make the command exit non-zero."""
    summary = report.get("summary", {})
    if not summary.get("trusted"):
        return True
    days = summary.get("days_remaining")
    if days is not None and days < 0:
        return True
    if summary.get("expires_within_threshold"):
        return True
    return bool(strict and summary.get("issues"))


# --------------------------------------------------------------------------
# PRESENTATION
# --------------------------------------------------------------------------


GRADE_COLOURS = {"A": "green", "B": "green", "C": "yellow", "D": "yellow",
                 "E": "red", "F": "red"}


def present(report: dict) -> dict:
    """Render an audit for a human."""
    if is_quiet():
        return report

    summary = report.get("summary", {})
    if not summary:
        for problem in report.get("errors", []):
            err(problem)
        return report

    letter = str(summary.get("grade", "?"))
    colour = GRADE_COLOURS.get(letter[:1], "white")
    host = f"{report['target']}:{report['meta'].get('port', DEFAULT_PORT)}"

    console.print(
        Panel.fit(
            f"[bold {colour}]grade {letter}[/bold {colour}]   [white]{host}[/white]\n"
            f"[dim]{report['meta'].get('trust_explanation', '')}[/dim]",
            border_style=colour,
            title="[bold cyan]TLS Audit[/bold cyan]",
        )
    )

    certificate_items = {
        "subject", "issuer", "serial", "valid-from", "valid-until",
        "days-remaining", "key", "signature-algorithm", "san-dns", "san-ip",
        "ocsp", "ca-issuers", "certificate-transparency", "fingerprint-sha256",
        "negotiated", "negotiated-cipher", "alpn", "verify-error",
    }
    table = Table(title="Certificate", header_style="bold cyan")
    table.add_column("FIELD", style="cyan")
    table.add_column("VALUE", style="white", overflow="fold")
    rows = 0
    for finding in report.get("findings", []):
        item = str(finding.get("item", ""))
        if item not in certificate_items:
            continue
        value = str(finding.get("value", ""))
        if item == "days-remaining" and isinstance(finding.get("value"), int):
            days = finding["value"]
            tone = "red" if days < 14 else ("yellow" if days < 30 else "green")
            value = f"[{tone}]{days}[/{tone}]"
        detail = str(finding.get("detail", ""))
        table.add_row(item, f"{value}  [dim]{detail}[/dim]" if detail else value)
        rows += 1
    if rows:
        console.print(table)

    protocols = [finding for finding in report.get("findings", [])
                 if str(finding.get("item", "")).startswith("protocol:")]
    if protocols:
        protocol_table = Table(title="Protocol Support", header_style="bold cyan")
        protocol_table.add_column("VERSION", style="cyan")
        protocol_table.add_column("STATUS", style="green")
        protocol_table.add_column("CIPHER / REASON", style="white", overflow="fold")
        for finding in protocols:
            name = str(finding["item"]).split(":", 1)[1]
            ok = finding.get("value") == "supported"
            if ok and name in LEGACY_PROTOCOLS:
                tone = "red"
            elif ok:
                tone = "green"
            else:
                tone = "dim"
            protocol_table.add_row(name, f"[{tone}]{finding.get('value')}[/{tone}]",
                                   str(finding.get("detail", "")))
        console.print(protocol_table)

    issues = [finding for finding in report.get("findings", [])
              if str(finding.get("item", "")).startswith("weakness:")]
    if issues:
        issue_table = Table(title=f"Weaknesses ({len(issues)})", header_style="bold red")
        issue_table.add_column("SEVERITY", style="red")
        issue_table.add_column("ISSUE", style="cyan")
        issue_table.add_column("DETAIL", style="white", overflow="fold")
        for finding in issues:
            tone = {"high": "red", "medium": "yellow", "low": "dim"}.get(
                finding.get("severity", ""), "white")
            issue_table.add_row(f"[{tone}]{finding.get('severity', '')}[/{tone}]",
                                str(finding["item"]).split(":", 1)[1],
                                str(finding.get("detail", "")))
        console.print(issue_table)
    else:
        console.print("[green]+[/green] No weaknesses found - clean configuration.")

    if summary.get("expires_within_threshold"):
        warn(f"Certificate expires within the requested threshold "
             f"({summary.get('days_remaining')} day(s) left).")

    for problem in report.get("errors", []):
        err(problem)
    return report


def tls_audit(target: str | None = None, **kwargs) -> dict:
    """Menu / interactive entry point."""
    if not target:
        from core.utils import ask

        target = ask("Host [host or host:port]")
    return present(audit(target, **kwargs))
