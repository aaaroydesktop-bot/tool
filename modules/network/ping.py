"""
ICMP ping engine.

The toolkit targets Termux, where ICMP from the Android kernel is *not* always
permitted and the ``ping`` binary may be missing.  Every liveness check here
therefore falls back to TCP probes: a refused connection still proves a host is
up, because something answered with a RST.
"""

from __future__ import annotations

import concurrent.futures
import platform
import re
import socket
import subprocess
import time

from rich.table import Table

from core import report as reportlib
from core.console import console, err, info, is_quiet
from core.netutil import gateway_for, human_duration, parse_target

WINDOWS = platform.system().lower().startswith("win")

#: Ports probed by the TCP fallback, in the order that finds hosts fastest.
FALLBACK_PORTS = (80, 443, 22, 53, 8080, 445, 139, 8000, 1)

_TIME_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.I)
_TTL_RE = re.compile(r"ttl[=:]\s*(\d+)", re.I)
_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

_OS_BY_TTL = [(64, "Linux / Android"), (128, "Windows"), (255, "Network device")]


# --------------------------------------------------------------------------
# ADDRESS HELPERS
# --------------------------------------------------------------------------


def get_local_ip() -> str:
    """Local address of the interface that reaches the internet."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("1.1.1.1", 80))
            return sock.getsockname()[0]
        finally:
            sock.close()
    except OSError:
        return "127.0.0.1"


def get_router_ip(local_ip: str | None = None) -> str:
    """Default gateway, read from /proc/net/route when available."""
    try:
        with open("/proc/net/route", "r", errors="ignore") as handle:
            for line in handle.readlines()[1:]:
                fields = line.split()
                if len(fields) > 3 and fields[1] == "00000000":
                    raw = bytes.fromhex(fields[2])[::-1]
                    return ".".join(str(byte) for byte in raw)
    except OSError:
        pass
    return gateway_for(local_ip or get_local_ip()) or "unknown"


def detect_os(ttl) -> str:
    try:
        value = int(ttl)
    except (TypeError, ValueError):
        return "Unknown"
    for ceiling, label in _OS_BY_TTL:
        if value <= ceiling:
            return label
    return "Unknown"


# --------------------------------------------------------------------------
# PING
# --------------------------------------------------------------------------


def _command(host: str, timeout: float, ttl: int | None = None) -> list[str]:
    if WINDOWS:
        if ttl is None:
            return ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
        return ["ping", "-n", "1", "-w", str(int(timeout * 1000)), "-i", str(ttl), host]
    if ttl is None:
        return ["ping", "-c", "1", "-W", str(max(1, int(round(timeout)))), host]
    return ["ping", "-c", "1", "-W", str(max(1, int(round(timeout)))), "-t", str(ttl), host]


def ping_once(host: str, timeout: float = 1.0, ttl: int | None = None) -> dict | None:
    """Send a single ICMP echo.  Returns a dict or ``None`` on no reply."""
    try:
        completed = subprocess.run(
            _command(host, timeout, ttl),
            capture_output=True,
            text=True,
            timeout=timeout + 3,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    output = completed.stdout or ""

    reachable = (
        completed.returncode == 0
        or "ttl=" in output.lower()
        or "time<1ms" in output.lower()
        or "time to live exceeded" in output.lower()
        or "ttl expired in transit" in output.lower()
    )
    if not reachable:
        return None

    time_match = _TIME_RE.search(output)
    ttl_match = _TTL_RE.search(output)
    ip_match = _IP_RE.search(output)

    if time_match:
        elapsed = float(time_match.group(1))
    elif "time<1ms" in output.lower():
        elapsed = 0.5
    else:
        elapsed = None

    return {
        "host": host,
        "ip": ip_match.group(1) if ip_match else host,
        "time_ms": elapsed,
        "ttl": int(ttl_match.group(1)) if ttl_match else None,
        "os": detect_os(ttl_match.group(1)) if ttl_match else "Unknown",
    }


def tcp_probe(host: str, ports=FALLBACK_PORTS, timeout: float = 0.7) -> bool:
    """
    Liveness check without ICMP.

    A successful connect *or* an explicit refusal both mean the host is up; only
    timeouts are treated as "no answer".
    """
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            code = sock.connect_ex((host, port))
        except OSError:
            code = -1
        finally:
            sock.close()
        if code in (0, 111, 61, 10061):
            return True
    return False


def host_alive(host: str, timeout: float = 0.8, use_icmp: bool = True) -> bool:
    """Ping first, then fall back to TCP when ICMP is unavailable."""
    if use_icmp and ping_once(host, timeout=timeout):
        return True
    return tcp_probe(host, timeout=timeout)


def ping_test(target: str | None = None, count: int = 4, timeout: float = 1.0,
              interval: float = 0.25) -> dict:
    """Repeated ping with latency statistics."""
    if not target:
        from core.utils import ask

        target = ask("Target IP/Domain")

    host, _ = parse_target(target)
    report = reportlib.new_report("ping_test", host, count=count, interval=interval)
    info(f"Pinging {host} x{count}...")

    started = time.time()
    replies: list[dict] = []
    ip = None

    for _ in range(max(1, count)):
        reply = ping_once(host, timeout=timeout)
        if reply:
            ip = ip or reply["ip"]
            replies.append(reply)
            reportlib.add_finding(
                report,
                ip=reply["ip"],
                time_ms=reply["time_ms"],
                ttl=reply["ttl"],
                os=reply["os"],
            )
        else:
            reportlib.add_finding(report, ip="*", time_ms=None, ttl=None, os="timeout")
        time.sleep(interval)

    times = [r["time_ms"] for r in replies if r["time_ms"] is not None]
    jitter = None
    if len(times) > 1:
        diffs = [abs(b - a) for a, b in zip(times, times[1:])]
        jitter = round(sum(diffs) / len(diffs), 3)

    loss = round((len(report["findings"]) - len(replies)) / max(1, len(report["findings"])) * 100, 1)

    reportlib.finish(
        report,
        time.time() - started,
        ip=ip,
        sent=len(report["findings"]),
        received=len(replies),
        loss_percent=loss,
        min_ms=round(min(times), 3) if times else None,
        avg_ms=round(sum(times) / len(times), 3) if times else None,
        max_ms=round(max(times), 3) if times else None,
        jitter_ms=jitter,
        alive=bool(replies),
    )
    return _present(report)


def ping_sweep(hosts, workers: int = 128, timeout: float = 0.8,
               on_result=None) -> list[dict]:
    """Concurrently check many hosts.  Returns the ones that answered."""
    found: list[dict] = []

    def worker(host: str):
        return host if host_alive(host, timeout=timeout) else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for host in pool.map(worker, list(hosts), chunksize=4):
            if host:
                found.append({"ip": host})
                if on_result:
                    on_result(host)

    return sorted(found, key=lambda item: tuple(int(p) for p in item["ip"].split(".")))


def _present(report: dict) -> dict:
    if is_quiet():
        return report
    summary = report.get("summary", {})
    table = Table(title=f"Ping - {report['target']}", header_style="bold cyan")
    table.add_column("IP", style="cyan")
    table.add_column("TIME", style="green")
    table.add_column("TTL", style="magenta")
    table.add_column("OS GUESS", style="yellow")
    for finding in report.get("findings", []):
        time_ms = finding.get("time_ms")
        table.add_row(
            str(finding.get("ip", "")),
            "timeout" if time_ms is None else f"{time_ms} ms",
            str(finding.get("ttl") or "-"),
            str(finding.get("os", "")),
        )
    console.print(table)

    if summary:
        console.print(
            f"[green]+[/green] {summary.get('received', 0)}/{summary.get('sent', 0)} replies  "
            f"[yellow]loss {summary.get('loss_percent')}%[/yellow]  "
            f"min/avg/max "
            f"{summary.get('min_ms')}/{summary.get('avg_ms')}/{summary.get('max_ms')} ms  "
            f"[dim]jitter {summary.get('jitter_ms')}[/dim]"
        )
        console.print(f"[cyan]+[/cyan] Duration: {human_duration(report.get('duration'))}")

    for error in report.get("errors", []):
        err(error)
    return report
