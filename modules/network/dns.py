"""DNS resolution: forward, reverse and (when available) record types."""

from __future__ import annotations

import socket
import subprocess

from rich.table import Table

from core import report as reportlib
from core.console import console, err, info, is_quiet
from core.environment import have
from core.netutil import is_ip, parse_target


def _record_types(host: str) -> list[dict]:
    """MX / NS / TXT via nslookup when dnsutils is installed."""
    if not have("nslookup"):
        return []
    findings = []
    for rtype in ("MX", "NS", "TXT"):
        try:
            output = subprocess.run(
                ["nslookup", f"-type={rtype}", host],
                capture_output=True, text=True, timeout=12,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        for line in output.splitlines():
            text = line.strip()
            if not text or "=" in text.split(" ")[0]:
                continue
            lowered = text.lower()
            if lowered.startswith(("server:", "address:", ";", "non-authoritative")):
                continue
            findings.append({"record": rtype, "value": text})
    return findings


def lookup(target: str | None = None) -> dict:
    """Resolve ``target`` and return a DNS report dict."""
    if not target:
        from core.utils import ask

        target = ask("Domain/IP")

    host, _ = parse_target(target)
    report = reportlib.new_report("dns_lookup", host)
    info(f"Resolving {host}...")

    if is_ip(host):
        name = None
        try:
            name = socket.gethostbyaddr(host)[0]
        except OSError:
            pass
        reportlib.add_finding(report, record="PTR", value=name or "no reverse record")
        reportlib.finish(report, resolved=bool(name), ip=host)
        return _present(report)

    addresses: list[str] = []
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            ip = sockaddr[0]
            if ip not in addresses:
                addresses.append(ip)
                reportlib.add_finding(
                    report,
                    record="AAAA" if family == socket.AF_INET6 else "A",
                    value=ip,
                )
    except OSError as exc:
        reportlib.add_error(report, f"resolution failed: {exc}")

    reportlib.finish(report, resolved=bool(addresses), ip=addresses[0] if addresses else None)

    for record in _record_types(host):
        reportlib.add_finding(report, **record)
    if not have("nslookup"):
        report["meta"]["hint"] = "install dnsutils for MX/NS/TXT records"

    return _present(report)


def _present(report: dict) -> dict:
    if is_quiet():
        return report
    findings = report.get("findings", [])
    if findings:
        table = Table(title=f"DNS - {report['target']}", header_style="bold cyan")
        table.add_column("TYPE", style="cyan")
        table.add_column("VALUE", style="green")
        for finding in findings:
            table.add_row(finding.get("record", ""), str(finding.get("value", "")))
        console.print(table)
    for error in report.get("errors", []):
        err(error)
    return report
