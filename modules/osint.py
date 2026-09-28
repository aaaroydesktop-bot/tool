"""
Domain intelligence.

RDAP is tried first because it returns structured JSON over HTTPS; the classic
WHOIS protocol is kept as a fallback for TLDs without an RDAP service.
"""

from __future__ import annotations

from rich.table import Table

from core import http
from core import report as reportlib
from core.console import console, err, info, is_quiet
from core.environment import have
from core.netutil import parse_target

RDAP_BASE = "https://rdap.org/domain/"

_VALUED_KEYS = ("ldhName", "handle", "status", "nameserver", "registrar", "event")


def _from_rdap(domain: str, report: dict) -> bool:
    try:
        data = http.get_json(f"{RDAP_BASE}{domain}", timeout=12)
    except Exception as exc:
        reportlib.add_error(report, f"rdap: {exc}")
        return False

    if not isinstance(data, dict) or data.get("errorCode"):
        return False

    report["meta"]["source"] = "RDAP"
    reportlib.add_finding(report, field="domain", value=data.get("ldhName") or domain)
    if data.get("handle"):
        reportlib.add_finding(report, field="handle", value=data["handle"])

    for event in data.get("events", []) or []:
        reportlib.add_finding(
            report,
            field=f"date:{event.get('eventAction', 'event')}",
            value=str(event.get("eventDate", ""))[:10],
        )

    for entity in data.get("entities", []) or []:
        roles = ",".join(entity.get("roles", []) or [])
        if "registrar" not in roles:
            continue
        vcard = entity.get("vcardArray", [None, []])[1]
        label = next(
            (item[3] for item in vcard if item[0] == "fn"),
            entity.get("handle", "registrar"),
        )
        reportlib.add_finding(report, field="registrar", value=label)
        for item in vcard:
            if item[0] == "email":
                reportlib.add_finding(report, field="registrar:email", value=item[3])

    for server in data.get("nameservers", []) or []:
        reportlib.add_finding(report, field="nameserver", value=server.get("ldhName", ""))

    for status in data.get("status", []) or []:
        reportlib.add_finding(report, field="status", value=status)

    if data.get("secureDNS"):
        reportlib.add_finding(
            report, field="dnssec",
            value="signed" if data["secureDNS"].get("delegationSigned") else "not signed",
        )
    return True


def _from_whois_library(domain: str, report: dict) -> bool:
    try:
        import whois  # python-whois
    except ImportError:
        return False

    try:
        data = whois.whois(domain)
    except Exception as exc:
        reportlib.add_error(report, f"whois: {exc}")
        return False

    report["meta"]["source"] = "python-whois"
    for key, value in dict(data).items():
        if value in (None, "", [], {}):
            continue
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value)
        reportlib.add_finding(report, field=key, value=str(value)[:200])
    return True


def _from_whois_cli(domain: str, report: dict) -> bool:
    if not have("whois"):
        return False
    import subprocess

    try:
        output = subprocess.run(
            ["whois", domain], capture_output=True, text=True, timeout=20
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return False

    if not output.strip():
        return False

    report["meta"]["source"] = "whois CLI"
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key and value and len(report["findings"]) < 60:
            reportlib.add_finding(report, field=key.lower(), value=value[:200])
    return True


def whois_lookup(target: str | None = None) -> dict:
    """Look up registration data for ``target``."""
    if not target:
        from core.utils import ask

        target = ask("Domain")

    try:
        domain, _ = parse_target(target)
    except ValueError as exc:
        report = reportlib.new_report("whois_lookup", str(target))
        reportlib.add_error(report, str(exc))
        reportlib.finish(report, resolved=False)
        return report

    report = reportlib.new_report("whois_lookup", domain)
    info(f"Looking up registration data for {domain}...")

    for strategy in (_from_rdap, _from_whois_library, _from_whois_cli):
        if strategy(domain, report):
            reportlib.finish(report, resolved=True, source=report["meta"].get("source"))
            return _present(report)

    reportlib.add_error(report, "no WHOIS/RDAP source returned data")
    reportlib.finish(report, resolved=False)
    return _present(report)


def _present(report: dict) -> dict:
    if is_quiet():
        return report
    findings = report.get("findings", [])
    if findings:
        table = Table(title=f"WHOIS - {report['target']}", header_style="bold cyan")
        table.add_column("FIELD", style="cyan", overflow="fold")
        table.add_column("VALUE", style="green", overflow="fold")
        for finding in findings:
            table.add_row(str(finding.get("field", "")), str(finding.get("value", "")))
        console.print(table)
    for error in report.get("errors", []):
        err(error)
    return report
