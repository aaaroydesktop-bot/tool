"""Traceroute: uses the system tool when present, else a ping TTL walk."""

from __future__ import annotations

import platform
import re
import subprocess

from rich.table import Table

from core import report as reportlib
from core.console import console, err, info, is_quiet
from core.environment import have
from core.netutil import parse_target

WINDOWS = platform.system().lower().startswith("win")

_IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
_TIME_RE = re.compile(r"([\d.]+)\s*ms", re.I)
_HOP_RE = re.compile(r"^\s*(\d{1,2})\s+")


def _parse_external(output: str) -> list[dict]:
    hops: list[dict] = []
    for line in output.splitlines():
        match = _HOP_RE.match(line)
        if not match:
            continue
        hop = int(match.group(1))
        ip_match = _IP_RE.search(line)
        times = [float(t) for t in _TIME_RE.findall(line)]
        hops.append({
            "hop": hop,
            "ip": ip_match.group(1) if ip_match else "*",
            "rtt_ms": round(min(times), 2) if times else None,
        })
    return hops


def trace(target: str | None = None, max_hops: int = 30, timeout: float = 2) -> dict:
    """Trace the path to ``target``."""
    if not target:
        from core.utils import ask

        target = ask("Target IP/Domain")

    host, _ = parse_target(target)
    report = reportlib.new_report("traceroute", host, max_hops=max_hops)
    info(f"Tracing route to {host} (max {max_hops} hops)...")

    hops: list[dict] = []

    if have("traceroute") or (WINDOWS and have("tracert")):
        command = ["tracert", "-h", str(max_hops), "-w", str(int(timeout * 1000)), host] \
            if WINDOWS else ["traceroute", "-m", str(max_hops), "-w", str(timeout), host]
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, timeout=max_hops * (timeout + 2)
            )
            hops = _parse_external(completed.stdout or "")
        except (OSError, subprocess.SubprocessError) as exc:
            reportlib.add_error(report, f"system traceroute failed: {exc}")

    if not hops:
        report["meta"]["method"] = "ping TTL walk"
        hops = _ping_walk(host, max_hops, timeout)
    else:
        report["meta"]["method"] = "system traceroute"

    for hop in hops:
        reportlib.add_finding(report, **hop)

    reached = bool(hops) and hops[-1].get("ip") != "*"
    reportlib.finish(report, hops=len(hops), reached=reached)
    return _present(report)


def _ping_walk(host: str, max_hops: int, timeout: float) -> list[dict]:
    """Fallback used when traceroute is not installed (common on Android)."""
    from .ping import ping_once

    hops: list[dict] = []
    for ttl in range(1, max_hops + 1):
        completed = subprocess.run(
            ["ping", "-n", "1", "-w", str(int(timeout * 1000)), "-i", str(ttl), host]
            if WINDOWS
            else ["ping", "-c", "1", "-W", str(max(1, int(round(timeout)))), "-t", str(ttl), host],
            capture_output=True, text=True, timeout=timeout + 3,
        )
        output = completed.stdout or ""
        lowered = output.lower()

        if "time to live exceeded" in lowered or "ttl expired in transit" in lowered:
            match = re.search(r"(?:from)\s+(\d+\.\d+\.\d+\.\d+)", lowered) or _IP_RE.search(output)
            hops.append({
                "hop": ttl,
                "ip": match.group(1) if match else "*",
                "rtt_ms": None,
                "note": "ttl exceeded",
            })
            continue

        reply = ping_once(host, timeout=timeout, ttl=ttl)
        if reply:
            hops.append({"hop": ttl, "ip": reply["ip"], "rtt_ms": reply["time_ms"], "note": "reached"})
            break

        hops.append({"hop": ttl, "ip": "*", "rtt_ms": None, "note": "no reply"})

    return hops


def _present(report: dict) -> dict:
    if is_quiet():
        return report
    findings = report.get("findings", [])
    if findings:
        table = Table(title=f"Traceroute - {report['target']}", header_style="bold cyan")
        table.add_column("HOP", style="cyan", justify="right")
        table.add_column("ADDRESS", style="green")
        table.add_column("RTT", style="yellow", justify="right")
        table.add_column("NOTE", style="dim")
        for finding in findings:
            rtt = finding.get("rtt_ms")
            table.add_row(
                str(finding.get("hop", "")),
                str(finding.get("ip", "")),
                "-" if rtt is None else f"{rtt} ms",
                str(finding.get("note", "")),
            )
        console.print(table)
    for error in report.get("errors", []):
        err(error)
    return report
