"""
Local network discovery.

Ordering matters on Android: sweep for live hosts *first* (which populates the
kernel ARP cache), then read the neighbour table, so MAC addresses appear
without root and without raw sockets.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import platform
import re
import socket
import subprocess

from rich.table import Table

from core import report as reportlib
from core.console import console, err, info, is_quiet
from core.environment import have, is_root

WINDOWS = platform.system().lower().startswith("win")

_ARP_LINE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s+.*?([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")


# --------------------------------------------------------------------------
# INTERFACE INFORMATION
# --------------------------------------------------------------------------


def local_ip() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("1.1.1.1", 80))
            return sock.getsockname()[0]
        finally:
            sock.close()
    except OSError:
        return "127.0.0.1"


def subnet_of(ip: str) -> ipaddress.IPv4Network | None:
    """Best-effort /24 around ``ip`` (Android exposes no netmask without root)."""
    try:
        return ipaddress.ip_network(f"{ip}/24", strict=False)
    except ValueError:
        return None


def wifi_info() -> dict:
    """SSID / link details via termux-api, when the addon is installed."""
    if not have("termux-wifi-connectioninfo"):
        return {}
    try:
        import json

        raw = subprocess.run(
            ["termux-wifi-connectioninfo"], capture_output=True, text=True, timeout=10
        ).stdout
        data = json.loads(raw or "{}")
        return {
            "ssid": data.get("ssid"),
            "bssid": data.get("bssid"),
            "link_speed_mbps": data.get("link_speed_mbps"),
            "frequency_mhz": data.get("frequency_mhz"),
            "rssi": data.get("rssi"),
        }
    except Exception:
        return {}


# --------------------------------------------------------------------------
# ARP / NEIGHBOUR TABLE
# --------------------------------------------------------------------------


def arp_table() -> dict[str, str]:
    """Map IP -> MAC using whatever the platform offers."""
    table: dict[str, str] = {}

    for path in ("/proc/net/arp",):
        try:
            with open(path, "r", errors="ignore") as handle:
                for line in handle.readlines()[1:]:
                    fields = line.split()
                    if len(fields) >= 4 and fields[3] != "00:00:00:00:00:00":
                        table[fields[0]] = fields[3].lower()
        except OSError:
            pass

    if not table and have("ip"):
        try:
            output = subprocess.run(
                ["ip", "neigh", "show"], capture_output=True, text=True, timeout=10
            ).stdout
            for line in output.splitlines():
                match = _ARP_LINE.search(line)
                if match:
                    table[match.group(1)] = match.group(2).lower()
        except (OSError, subprocess.SubprocessError):
            pass

    if not table and WINDOWS:
        try:
            output = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10).stdout
            for line in output.splitlines():
                match = _ARP_LINE.search(line.replace("-", ":"))
                if match:
                    table[match.group(1)] = match.group(2).lower()
        except (OSError, subprocess.SubprocessError):
            pass

    return table


def hostname_of(ip: str, timeout: float = 1.0) -> str:
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""
    finally:
        socket.setdefaulttimeout(previous)


# --------------------------------------------------------------------------
# DISCOVERY
# --------------------------------------------------------------------------


def discover(network: str | None = None, workers: int = 128, timeout: float = 0.8,
             resolve_names: bool = False, vendor: bool = False,
             show_progress: bool | None = None) -> dict:
    """
    Sweep a local subnet and describe every device that answers.
    """
    from .ping import host_alive

    base_ip = local_ip()
    net = None
    if network:
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError:
            net = None
    net = net or subnet_of(base_ip)
    if net is None:
        report = reportlib.new_report("local_network_scan", base_ip)
        reportlib.add_error(report, "could not determine the local subnet")
        reportlib.finish(report, devices=0)
        return report

    hosts = [str(host) for host in net.hosts()]
    report = reportlib.new_report(
        "local_network_scan",
        str(net),
        interface_ip=base_ip,
        gateway=_gateway(),
        hosts_probed=len(hosts),
    )
    info(f"Scanning {net} ({len(hosts)} addresses)...")

    if show_progress is None:
        show_progress = not is_quiet() and len(hosts) > 32

    alive: list[str] = []

    def worker(host: str):
        return host if host_alive(host, timeout=timeout) else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        if show_progress:
            from rich.progress import Progress as _Progress

            with _Progress() as progress:
                task = progress.add_task("[green]Probing...", total=len(hosts))
                for result in pool.map(worker, hosts, chunksize=8):
                    progress.update(task, advance=1)
                    if result:
                        alive.append(result)
        else:
            for result in pool.map(worker, hosts, chunksize=8):
                if result:
                    alive.append(result)

    # MACs only show up once the sweep has populated the neighbour cache.
    neighbours = arp_table()

    for ip in sorted(alive, key=lambda value: tuple(int(p) for p in value.split("."))):
        finding = {
            "ip": ip,
            "mac": neighbours.get(ip, ""),
            "hostname": hostname_of(ip) if resolve_names else "",
        }
        if vendor and finding["mac"]:
            from .vendor import OFFLINE_OUI

            prefix = finding["mac"].replace(":", "").upper()[:6]
            finding["vendor"] = OFFLINE_OUI.get(prefix, "")
        reportlib.add_finding(report, **finding)

    wifi = wifi_info()
    report["meta"].update({k: v for k, v in wifi.items() if v is not None})

    reportlib.finish(
        report,
        devices=len(alive),
        routable=len([ip for ip in alive if ip != base_ip]),
    )
    return _present(report)


def _gateway() -> str:
    from .ping import get_router_ip

    return get_router_ip()


def local_network_scan(network: str | None = None, **kwargs) -> dict:
    """Menu/CLI entry point."""
    if not network:
        from core.utils import ask

        answer = ask("Network [blank = auto-detect]", default="")
        network = answer or None
    return discover(network, **kwargs)


def _present(report: dict) -> dict:
    if is_quiet():
        return report
    findings = report.get("findings", [])
    table = Table(title=f"Local Network - {report['target']}", header_style="bold cyan")
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="yellow")
    table.add_column("HOSTNAME", style="green")
    if any(f.get("vendor") for f in findings):
        table.add_column("VENDOR", style="magenta")
    for finding in findings:
        row = [finding.get("ip", ""), finding.get("mac", ""), finding.get("hostname", "")]
        if any(f.get("vendor") for f in findings):
            row.append(finding.get("vendor", ""))
        table.add_row(*row)
    console.print(table)

    summary = report.get("summary", {})
    console.print(f"[green]+[/green] Devices found: {summary.get('devices', 0)}")
    meta = report.get("meta", {})
    if meta.get("gateway"):
        console.print(f"[cyan]+[/cyan] Gateway: {meta['gateway']}")
    if meta.get("ssid"):
        console.print(
            f"[cyan]+[/cyan] Wi-Fi: {meta['ssid']} "
            f"[dim](rssi {meta.get('rssi')}, {meta.get('link_speed_mbps')} Mbps)[/dim]"
        )
    if not is_root():
        console.print("[dim]* MAC addresses need the ARP cache; run as root for full detail[/dim]")

    for error in report.get("errors", []):
        err(error)
    return report
