"""HTTP response headers plus a small security-header audit."""

from __future__ import annotations

import socket
import time
from urllib.parse import urlparse

from rich.table import Table

from core import http
from core import report as reportlib
from core.console import console, err, info, is_quiet

SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", "forces HTTPS for future visits"),
    "content-security-policy": ("CSP", "mitigates XSS and injection"),
    "x-frame-options": ("X-Frame-Options", "blocks clickjacking"),
    "x-content-type-options": ("X-Content-Type-Options", "stops MIME sniffing"),
    "referrer-policy": ("Referrer-Policy", "limits referrer leakage"),
    "permissions-policy": ("Permissions-Policy", "restricts browser features"),
    "cross-origin-opener-policy": ("COOP", "isolates the browsing context"),
}


def fetch(url: str | None = None, timeout: float = 10, follow: bool = True) -> dict:
    """Fetch ``url`` and return a header report dict."""
    if not url:
        from core.utils import ask

        url = ask("URL")

    url = http.normalize_url(url)
    report = reportlib.new_report("http_headers", url, requested=url)
    info(f"Requesting {url}...")

    started = time.time()
    try:
        response = http.get(url, timeout=timeout, allow_redirects=follow)
    except Exception as exc:
        reportlib.add_error(report, str(exc))
        reportlib.finish(report, time.time() - started, reachable=False)
        return _present(report)

    report["meta"]["final_url"] = response.url
    report["meta"]["status"] = response.status_code
    report["meta"]["reason"] = response.reason
    report["meta"]["server_ip"] = _peer_ip(response.url)

    if response.history:
        chain = " -> ".join(f"{r.status_code} {r.url}" for r in response.history + [response])
        reportlib.add_finding(report, header="redirect-chain", value=chain)

    for name, value in response.headers.items():
        reportlib.add_finding(report, header=name, value=value[:300])

    lowered = {name.lower() for name in response.headers}
    for name, (label, why) in SECURITY_HEADERS.items():
        reportlib.add_finding(
            report,
            header=f"security:{label}",
            value="present" if name in lowered else f"MISSING - {why}",
        )

    if response.headers.get("Server"):
        reportlib.add_finding(report, header="fingerprint:server",
                              value=response.headers["Server"])
    for leak in ("X-Powered-By", "X-AspNet-Version", "X-Backend-Server", "Via"):
        if response.headers.get(leak):
            reportlib.add_finding(report, header=f"leak:{leak}",
                                  value=response.headers[leak])

    reportlib.finish(
        report,
        time.time() - started,
        reachable=True,
        status=response.status_code,
        headers=len(response.headers),
        missing_security=sum(
            1 for n in SECURITY_HEADERS if n not in lowered
        ),
        duration_ms=round((time.time() - started) * 1000, 1),
    )
    return _present(report)


def _peer_ip(url: str) -> str | None:
    """Resolve the host that actually served the response."""
    host = urlparse(url).hostname
    if not host:
        return None
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def _present(report: dict) -> dict:
    if is_quiet():
        return report
    findings = [f for f in report.get("findings", []) if not str(f.get("header", "")).startswith("security:")]
    security = [f for f in report.get("findings", []) if str(f.get("header", "")).startswith("security:")]
    leaks = [f for f in report.get("findings", []) if str(f.get("header", "")).startswith("leak:")]

    if findings:
        table = Table(title=f"HTTP Headers - {report['target']}", header_style="bold cyan")
        table.add_column("HEADER", style="cyan")
        table.add_column("VALUE", style="green", overflow="fold")
        for finding in findings:
            table.add_row(str(finding.get("header", "")), str(finding.get("value", "")))
        console.print(table)

    if security:
        table = Table(title="Security Headers", header_style="bold cyan")
        table.add_column("HEADER", style="cyan")
        table.add_column("STATUS", style="green", overflow="fold")
        for finding in security:
            status = str(finding.get("value", ""))
            colour = "green" if status == "present" else "red"
            table.add_row(
                str(finding.get("header", "")).replace("security:", ""),
                f"[{colour}]{status}[/{colour}]",
            )
        console.print(table)

    for finding in leaks:
        console.print(f"[yellow][!][/yellow] information leak: {finding['value']}")

    for error in report.get("errors", []):
        err(error)
    return report
