"""GeoIP / ISP lookup, including "what is my public IP"."""

from __future__ import annotations

from rich.table import Table

from core import http
from core import report as reportlib
from core.console import console, err, info, is_quiet

FIELDS = [
    "query", "country", "regionName", "city", "zip", "lat", "lon",
    "timezone", "isp", "org", "as", "mobile", "proxy", "hosting",
]


def lookup(ip: str | None = None) -> dict:
    """Look up ``ip``; when omitted, use this device's public IP."""
    if not ip:
        from core.utils import ask

        ip = ask("IP Address [blank = my public IP]", default="")

    report = reportlib.new_report("geoip_lookup", ip or "public-ip")

    if not ip:
        ip = http.public_ip()
        if not ip:
            reportlib.add_error(report, "could not determine public IP")
            reportlib.finish(report, resolved=False)
            return _present(report)
        report["target"] = ip
        report["meta"]["own_ip"] = True

    info(f"Looking up {ip}...")
    try:
        data = http.get_json(f"http://ip-api.com/json/{ip}?fields=status,message,"
                             "country,regionName,city,zip,lat,lon,timezone,isp,org,"
                             "as,mobile,proxy,hosting,query", timeout=10)
    except Exception as exc:
        reportlib.add_error(report, str(exc))
        reportlib.finish(report, resolved=False)
        return _present(report)

    if not data or data.get("status") == "fail":
        reportlib.add_error(report, (data or {}).get("message", "lookup failed"))
        reportlib.finish(report, resolved=False)
        return _present(report)

    for field in FIELDS:
        if data.get(field) not in (None, ""):
            reportlib.add_finding(report, field=field, value=data[field])

    reportlib.finish(
        report,
        resolved=True,
        country=data.get("country"),
        city=data.get("city"),
        isp=data.get("isp"),
    )
    return _present(report)


def _present(report: dict) -> dict:
    if is_quiet():
        return report
    findings = report.get("findings", [])
    if findings:
        table = Table(title=f"GeoIP - {report['target']}", header_style="bold cyan")
        table.add_column("FIELD", style="cyan")
        table.add_column("VALUE", style="green")
        for finding in findings:
            table.add_row(str(finding.get("field", "")), str(finding.get("value", "")))
        console.print(table)
    for error in report.get("errors", []):
        err(error)
    return report
