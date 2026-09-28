"""
TCP port scanner engine.

The engine returns *data* (a ``core.report`` shaped dict) and never prompts.
The interactive wrappers at the bottom render that data as Rich tables, which
is what keeps the menu and the CLI sharing one code path.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import select
import ssl
import socket
import time

from rich.table import Table

from core import report as reportlib
from core.console import console, info, is_quiet, say, warn
from core.netutil import (
    MAX_PORT,
    format_ports,
    human_duration,
    parse_ports,
    parse_target,
)
from .services import (
    SMART_PORTS,
    is_http_like,
    is_tls_like,
    risk_note,
    service_name,
)

DEFAULT_TIMEOUT = 0.6
DEFAULT_WORKERS = 256

#: Upper bound on filtered ports recorded per scan (keeps reports small).
MAX_FILTERED_KEPT = 4096

_HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: NetScan/5.0\r\n\r\n"

# connect_ex error codes worth distinguishing across platforms.
#   refused    : the host answered with a RST -> the port is closed
#   inprogress : the connect did not finish inside the timeout -> ask select()
#   timeout    : the platform reported 'timed out' -> treat as filtered
_REFUSED_ERRNOS = frozenset({61, 111, 10061})                # ECONNREFUSED
_INPROGRESS_ERRNOS = frozenset({11, 36, 115, 119, 10035, 10036})  # EAGAIN/INPROGRESS
_TIMEOUT_ERRNOS = frozenset({60, 110, 10060})                # ETIMEDOUT


# --------------------------------------------------------------------------
# TARGET RESOLUTION
# --------------------------------------------------------------------------


def resolve(host: str) -> tuple[str | None, str | None]:
    """Return ``(ip, error)``.  Accepts hostnames and literal IPs."""
    try:
        return socket.gethostbyname(host), None
    except OSError as exc:
        return None, str(exc)


def reverse_lookup(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


# --------------------------------------------------------------------------
# PROBES
# --------------------------------------------------------------------------


def probe_banner(sock: socket.socket, host: str, port: int, timeout: float) -> str:
    """Best-effort banner grab.  Never raises."""
    try:
        sock.settimeout(timeout)
        if is_http_like(port):
            try:
                sock.sendall(_HTTP_PROBE % host.encode())
            except OSError:
                pass
        chunk = sock.recv(512)
        if not chunk:
            return ""
        text = chunk.decode("utf-8", errors="ignore")
        first = text.splitlines()[0].strip() if text.strip() else ""
        return " ".join(first.split())[:120]
    except (socket.timeout, TimeoutError, OSError):
        return ""


def probe_tls(host: str, port: int, timeout: float) -> dict:
    """
    Grab the negotiated TLS parameters and a certificate fingerprint.

    Verification is intentionally disabled: the goal is to *describe* whatever
    is listening, including self-signed and expired certificates.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    raw = None
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        with context.wrap_socket(raw, server_hostname=host) as tls:
            details = {
                "tls_version": tls.version() or "",
                "tls_cipher": (tls.cipher() or ("",))[0],
            }
            try:
                der = tls.getpeercert(binary_form=True)
                if der:
                    details["tls_cert_sha256"] = hashlib.sha256(der).hexdigest()[:32]
            except (ssl.SSLError, ValueError, OSError):
                pass
            return details
    except (ssl.SSLError, socket.timeout, TimeoutError, OSError):
        return {}
    finally:
        if raw is not None:
            try:
                raw.close()
            except OSError:
                pass


def _resolve_incomplete_connect(sock: socket.socket, timeout: float) -> str:
    """
    Decide the real state of a connect that did not report success or refusal.

    POSIX usually returns ECONNREFUSED straight from ``connect_ex``, but Windows
    returns WSAEWOULDBLOCK whenever a timeout is set.  In that case the socket
    must be polled and the pending error read back via ``SO_ERROR`` - otherwise
    every closed port looks 'filtered', which is misleading.
    """
    try:
        _, writable, exceptional = select.select([], [sock], [sock], timeout)
    except (OSError, ValueError):
        return "filtered"

    if not writable and not exceptional:
        return "filtered"

    try:
        error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    except OSError:
        return "filtered"

    if error == 0:
        return "open"
    if error in _REFUSED_ERRNOS:
        return "closed"
    return "filtered"


def scan_port(host: str, port: int, timeout: float = DEFAULT_TIMEOUT,
              banner: bool = True, tls: bool = True) -> dict | None:
    """
    Scan a single TCP port.

    Returns ``None`` when the port is cleanly closed, otherwise a finding with a
    ``state`` of ``open`` or ``filtered``.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        code = sock.connect_ex((host, port))
    except OSError:
        sock.close()
        return None

    if code != 0:
        if code in _REFUSED_ERRNOS:
            state = "closed"
        elif code in _INPROGRESS_ERRNOS:
            state = _resolve_incomplete_connect(sock, timeout)
        else:
            state = "filtered"

        if state != "open":
            try:
                sock.close()
            except OSError:
                pass
            if state == "closed":
                return None
            return {"port": port, "state": "filtered", "service": service_name(port)}
        # 'open': the connect completed while we waited, so keep this socket -
        # it is already connected and ready for the banner probe.

    finding = {
        "port": port,
        "state": "open",
        "service": service_name(port),
    }

    if banner:
        text = probe_banner(sock, host, port, timeout)
        if text:
            finding["banner"] = text

    try:
        sock.close()
    except OSError:
        pass

    if tls and is_tls_like(port):
        finding.update(probe_tls(host, port, max(timeout, 1.0)))

    note = risk_note(port)
    if note:
        finding["risk"] = note

    return finding


# --------------------------------------------------------------------------
# ENGINE
# --------------------------------------------------------------------------


def scan_ports(target, ports=None, timeout: float = DEFAULT_TIMEOUT,
               workers: int = DEFAULT_WORKERS, banner: bool = True,
               tls: bool = True, show_progress: bool | None = None,
               keep_filtered: bool = False) -> dict:
    """
    Scan ``target`` and return a complete report dict.

    ``ports`` accepts anything :func:`core.netutil.parse_ports` understands.
    ``keep_filtered`` stores the list of silent ports in the report; the count
    is always present in ``summary``, so this defaults to off to keep reports
    (and JSON output) small.
    """
    host, _ = parse_target(target)

    try:
        port_list = parse_ports(ports)
    except ValueError as exc:
        # Bad input is a user error, not a crash: report it like any other.
        report = reportlib.new_report("port_scan", host)
        reportlib.add_error(report, str(exc))
        reportlib.finish(report, resolved=False, open=0)
        return report

    report = reportlib.new_report(
        "port_scan",
        host,
        ports_scanned=len(port_list),
        port_spec=format_ports(port_list) if len(port_list) <= 200 else f"{len(port_list)} ports",
        timeout=timeout,
        workers=workers,
    )

    started = time.time()
    ip, error = resolve(host)
    if not ip:
        reportlib.add_error(report, f"DNS resolution failed: {error}")
        reportlib.finish(report, time.time() - started, resolved=False, open=0)
        return report

    report["meta"]["ip"] = ip

    if show_progress is None:
        show_progress = not is_quiet() and len(port_list) > 200

    findings: list[dict] = []
    filtered_ports: list[int] = []

    def worker(port: int) -> dict | None:
        return scan_port(ip, port, timeout=timeout, banner=banner, tls=tls)

    def collect(result: dict | None) -> None:
        if not result:
            return
        if result["state"] == "open":
            findings.append(result)
        elif len(filtered_ports) < MAX_FILTERED_KEPT:
            filtered_ports.append(result["port"])

    if show_progress:
        from rich.progress import Progress

        with Progress() as progress:
            task = progress.add_task(f"[green]Scanning {ip}...", total=len(port_list))
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                for result in pool.map(worker, port_list, chunksize=32):
                    progress.update(task, advance=1)
                    collect(result)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for result in pool.map(worker, port_list, chunksize=32):
                collect(result)

    findings.sort(key=lambda item: item["port"])
    filtered_ports.sort()

    report["findings"] = findings
    if keep_filtered:
        # Only the port numbers are kept, so even a 65k-port scan stays small.
        report["filtered"] = filtered_ports
    filtered = len(filtered_ports)

    duration = time.time() - started
    reportlib.finish(
        report,
        duration,
        resolved=True,
        open=len(findings),
        filtered=filtered,
        closed=len(port_list) - len(findings) - filtered,
        duration_human=human_duration(duration),
    )
    return report


def scan_many(targets, ports=None, timeout: float = DEFAULT_TIMEOUT,
              workers: int = DEFAULT_WORKERS, on_target=None) -> list[dict]:
    """Scan several targets sequentially; ``on_target`` gets each report."""
    reports = []
    for target in targets:
        report = scan_ports(target, ports, timeout=timeout, workers=workers)
        reports.append(report)
        if on_target:
            on_target(report)
    return reports


def open_port_set(report: dict) -> set[int]:
    return {
        finding["port"]
        for finding in report.get("findings", [])
        if finding.get("state") == "open"
    }


def diff_reports(before: dict, after: dict) -> dict:
    """
    Compare two scans of the same target: what opened, what closed.

    Returns a report-shaped dict so it can be rendered or exported like any
    other result (used by ``--watch``).
    """
    left, right = open_port_set(before), open_port_set(after)
    opened, closed = sorted(right - left), sorted(left - right)

    report = reportlib.new_report(
        "scan_diff", after.get("target", before.get("target", "unknown")),
        compared_from=before.get("started"),
        compared_to=after.get("started"),
    )
    for port in opened:
        reportlib.add_finding(report, port=port, service=service_name(port), change="opened")
    for port in closed:
        reportlib.add_finding(report, port=port, service=service_name(port), change="closed")
    reportlib.finish(
        report,
        opened=len(opened),
        closed=len(closed),
        unchanged=len(left & right),
    )
    return report


# --------------------------------------------------------------------------
# RENDERING (used by the interactive menu)
# --------------------------------------------------------------------------


def render_table(report: dict, title: str = "Open Ports") -> Table:
    has_risk = any("risk" in finding for finding in report.get("findings", []))
    has_banner = any("banner" in finding for finding in report.get("findings", []))
    has_tls = any("tls_version" in finding for finding in report.get("findings", []))

    table = Table(title=title, header_style="bold cyan")
    table.add_column("PORT", style="cyan", justify="right")
    table.add_column("STATE", style="green")
    table.add_column("SERVICE", style="green")
    if has_banner:
        table.add_column("BANNER", style="yellow", overflow="fold")
    if has_tls:
        table.add_column("TLS", style="magenta")
    if has_risk:
        table.add_column("RISK", style="red", overflow="fold")

    for finding in report.get("findings", []):
        row = [
            str(finding.get("port", "")),
            finding.get("state", ""),
            finding.get("service", ""),
        ]
        if has_banner:
            row.append(finding.get("banner", ""))
        if has_tls:
            version = finding.get("tls_version", "")
            row.append(f"{version} {finding.get('tls_cipher', '')}".strip())
        if has_risk:
            row.append(finding.get("risk", ""))
        table.add_row(*row)

    return table


def print_report(report: dict, title: str = "Open Ports") -> None:
    """Render a scan report for a human, respecting quiet mode."""
    if is_quiet():
        return

    findings = report.get("findings", [])
    if findings:
        console.print(render_table(report, title))
    else:
        warn("No open ports found.")

    summary = report.get("summary", {})
    say(
        f"[green]+[/green] Open: [bold]{summary.get('open', 0)}[/bold]  "
        f"[yellow]Filtered: {summary.get('filtered', 0)}[/yellow]  "
        f"[dim]Closed: {summary.get('closed', 0)}[/dim]"
    )
    say(f"[cyan]+[/cyan] Scanned: {summary.get('duration_human', 'n/a')}")

    for error in report.get("errors", []):
        warn(error)


# --------------------------------------------------------------------------
# INTERACTIVE WRAPPERS (menu compatibility)
# --------------------------------------------------------------------------


def port_scan(target=None, start: int = 1, end: int = 1024) -> dict:
    """Scan a port range, prompting for the target when it is not given."""
    from core.utils import ask

    if not target:
        target = ask("Target IP/Domain")

    info(f"Scanning {target} (ports {start}-{end})...")
    report = scan_ports(target, range(start, end + 1))
    print_report(report, f"Port Scan - {target}")

    if report.get("errors"):
        from core.console import err

        err("; ".join(report["errors"]))

    return report


def auto_port_scan(target=None) -> dict:
    """High-signal scan over the well-known service ports."""
    from core.utils import ask

    if not target:
        target = ask("Target IP/Domain")

    info(f"Smart scan of {target} across {len(SMART_PORTS)} service ports...")
    report = scan_ports(target, SMART_PORTS)
    print_report(report, f"Smart Scan - {target}")

    if report.get("errors"):
        from core.console import err

        err("; ".join(report["errors"]))

    return report


def full_port_scan(target=None) -> dict:
    """Everything, 1-65535.  Slow: expect minutes on mobile data."""
    return port_scan(target, 1, MAX_PORT)
