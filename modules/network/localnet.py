"""
Local network discovery, ARP/neighbour tables and MAC addresses.

Android is the awkward platform here: since Android 10 the kernel hides
``/proc/net/*`` from non-root apps, and ``ip neigh`` needs netlink access it
often does not have.  So instead of assuming one source exists, every source is
attempted, merged, and *diagnosed* - you get told which one worked and, when
none did, exactly what would fix it.

Address families: this module speaks IPv4, which is what home routers hand out
to phones, TVs and IoT gadgets.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import platform
import re
import socket
import subprocess

from rich.table import Table

from core import report as reportlib
from core.console import console, err, info, is_quiet, note, warn
from core.environment import have, is_root
from core.netutil import gateway_for

WINDOWS = platform.system().lower().startswith("win")

#: Sources of neighbour data, in the order they are consulted.
NEIGHBOUR_SOURCES = (
    ("/proc/net/arp", "kernel ARP cache (needs readable /proc)"),
    ("ip neigh", "netlink neighbour table (iproute2)"),
    ("arp -a", "net-tools/busybox ARP dump"),
)

_IPV4 = r"(\d{1,3}(?:\.\d{1,3}){3})"
_MAC = r"([0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){5})"

_PROC_ROW = re.compile(rf"^{_IPV4}\s+\S+\s+\S+\s+{_MAC}")
_IPNEIGH_ROW = re.compile(rf"^{_IPV4}\s+.*?lladdr\s+{_MAC}", re.IGNORECASE)
# Windows 'arp -a':    192.168.0.1    5c-8c-9f-aa-bb-01    dynamic
_NETTOOLS_ROW = re.compile(rf"^{_IPV4}\s+{_MAC}")
# Linux/BSD 'arp -a':  ? (192.168.0.1) at 5c:8c:9f:aa:bb:01 [ether] on wlan0
_NETTOOLS_AT = re.compile(rf"\({_IPV4}\)\s+at\s+{_MAC}")
_ZERO_MAC = "00:00:00:00:00:00"
_SKIP_STATES = ("FAILED", "INCOMPLETE")


# --------------------------------------------------------------------------
# PARSING (pure: no I/O, so it is trivially testable)
# --------------------------------------------------------------------------


def _normalise_mac(mac: str) -> str:
    clean = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    if len(clean) != 12:
        return ""
    return ":".join(clean[i:i + 2] for i in range(0, 12, 2))


def parse_neighbours(text: str, fmt: str) -> dict[str, str]:
    """
    Parse a neighbour/ARP dump into ``{ip: mac}``.

    ``fmt`` is ``"proc"`` (``/proc/net/arp``), ``"ip-neigh"`` or ``"net-tools"``.

    Entries without a usable MAC (incomplete resolutions) are skipped, as are
    multicast/broadcast pseudo-entries - they are infrastructure chatter, not
    devices, and would otherwise show up as bogus rows.
    """
    table: dict[str, str] = {}

    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("IP address", "Address", "Interface")):
            continue

        ip = raw_mac = None

        if fmt == "ip-neigh":
            if any(state in stripped.upper() for state in _SKIP_STATES):
                continue
            match = _IPNEIGH_ROW.match(stripped)
        elif fmt == "proc":
            match = _PROC_ROW.match(stripped)
        else:
            # net-tools/busybox appear in two shapes; accept both.
            match = _NETTOOLS_ROW.match(stripped) or _NETTOOLS_AT.search(stripped)

        if match:
            ip, raw_mac = match.group(1), match.group(2)
        if ip is None:
            continue

        mac = _normalise_mac(raw_mac)
        # Unresolved entries and multicast/broadcast pseudo-addresses
        # (224.0.0.22, ff:ff:ff:ff:ff:ff) are not devices: drop them.
        if not mac or mac == _ZERO_MAC or is_multicast_mac(mac):
            continue
        table[ip] = mac.lower()

    return table


def _first_octet(mac: str) -> int | None:
    """First octet of a MAC, or ``None`` when the input is not a MAC at all."""
    clean = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    if len(clean) != 12:
        return None
    return int(clean[:2], 16)


def is_randomized_mac(mac: str) -> bool:
    """
    True for a locally administered (privacy) MAC.

    Android 10+ and iOS randomise the Wi-Fi MAC per network, which is why a
    device can appear with no vendor even when the ARP cache is readable.
    Anything that is not a 12-digit MAC (including free text) is not randomized.
    """
    first = _first_octet(mac)
    return first is not None and bool(first & 0b10)


def is_multicast_mac(mac: str) -> bool:
    """True for multicast/broadcast pseudo-addresses, which are never a device."""
    first = _first_octet(mac)
    return first is not None and bool(first & 0b01)


def mac_note(mac: str) -> str:
    """Short human note about a MAC's nature, or an empty string."""
    if not mac:
        return ""
    if is_multicast_mac(mac):
        return "multicast/broadcast"
    if is_randomized_mac(mac):
        return "randomized"
    return ""


def vendor_for(mac: str) -> str:
    """Offline OUI lookup; returns an empty string when unknown."""
    if not mac or is_randomized_mac(mac):
        return ""
    from .vendor import OFFLINE_OUI

    return OFFLINE_OUI.get(mac.replace(":", "").upper()[:6], "")


# --------------------------------------------------------------------------
# INTERFACE / WIFI INFORMATION
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


def subnet_of(ip: str, prefix: int = 24) -> ipaddress.IPv4Network | None:
    """Best-effort subnet around ``ip`` (Android hides the netmask without root)."""
    try:
        return ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    except ValueError:
        return None


def wifi_info() -> dict:
    """SSID / link details via termux-api, when the addon is installed."""
    if not have("termux-wifi-connectioninfo"):
        return {}
    try:
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
# NEIGHBOUR TABLE READING
# --------------------------------------------------------------------------


def _run(command: list[str]) -> tuple[str | None, str | None]:
    """Run a helper binary.  Returns ``(stdout, error)``."""
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        return None, "not installed"
    except (OSError, subprocess.SubprocessError) as exc:
        return None, str(exc)[:80]

    output = completed.stdout or ""
    if completed.returncode != 0 and not output.strip():
        return None, (completed.stderr or "command failed").strip().splitlines()[0][:80]
    return output, None


def read_neighbours() -> dict:
    """
    Merge every reachable neighbour source.

    Returns ``{"entries": {ip: mac}, "sources": [(name, how_many)], "problems":
    [(name, reason)]}`` so callers can both use the data and explain its gaps.
    """
    entries: dict[str, str] = {}
    sources: list[tuple[str, int]] = []
    problems: list[tuple[str, str]] = []

    # --- /proc/net/arp ------------------------------------------------
    name, why = NEIGHBOUR_SOURCES[0]
    try:
        with open("/proc/net/arp", "r", errors="ignore") as handle:
            proc_text = handle.read()
    except OSError as exc:
        problems.append((name, f"cannot read ({exc.strerror or exc})"))
    else:
        found = parse_neighbours(proc_text, "proc")
        if found:
            entries.update(found)
            sources.append((name, len(found)))
        else:
            problems.append((name, "readable but empty"))

    # --- ip neigh -----------------------------------------------------
    name = NEIGHBOUR_SOURCES[1][0]
    output, error = _run(["ip", "neigh", "show"])
    if error:
        problems.append((name, error))
    else:
        found = parse_neighbours(output or "", "ip-neigh")
        added = {ip: mac for ip, mac in found.items() if ip not in entries}
        if added:
            entries.update(added)
            sources.append((name, len(added)))
        elif not found:
            problems.append((name, "no entries"))

    # --- arp -a -------------------------------------------------------
    name = NEIGHBOUR_SOURCES[2][0]
    output, error = _run(["arp", "-a"])
    if error:
        problems.append((name, error))
    else:
        found = parse_neighbours(output or "", "net-tools")
        added = {ip: mac for ip, mac in found.items() if ip not in entries}
        if added:
            entries.update(added)
            sources.append((name, len(added)))
        elif not found:
            problems.append((name, "no entries"))

    return {"entries": entries, "sources": sources, "problems": problems}


def arp_table() -> dict[str, str]:
    """Just the ``{ip: mac}`` mapping (kept for callers that need no detail)."""
    return read_neighbours()["entries"]


def hostname_of(ip: str, timeout: float = 1.0) -> str:
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""
    finally:
        socket.setdefaulttimeout(previous)


def _ip_sort_key(value: str):
    try:
        return tuple(int(part) for part in value.split("."))
    except ValueError:
        return (0, 0, 0, 0)


# --------------------------------------------------------------------------
# ARP TABLE COMMAND
# --------------------------------------------------------------------------


def arp_report(network: str | None = None, scan: bool = False, vendor: bool = False,
               workers: int = 128, timeout: float = 0.8) -> dict:
    """
    Report the neighbour cache, optionally filling it with a sweep first.

    ``scan=True`` pings the subnet so silent devices reveal themselves, which is
    also what makes the kernel populate its ARP cache in the first place.
    """
    interface_ip = local_ip()
    net = None
    if network:
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError:
            net = None
    net = net or subnet_of(interface_ip)

    report = reportlib.new_report(
        "arp_table",
        str(net) if net else interface_ip,
        interface_ip=interface_ip,
        gateway=_gateway(interface_ip),
        swept=bool(scan),
    )

    if scan:
        if net is None:
            reportlib.add_error(report, "cannot sweep: unknown subnet")
        else:
            from .ping import ping_sweep

            hosts = [str(host) for host in net.hosts()]
            info(f"Probing {len(hosts)} addresses to populate the ARP cache...")
            ping_sweep(hosts, workers=workers, timeout=timeout)

    cache = read_neighbours()
    report["meta"]["sources"] = [f"{name} ({count})" for name, count in cache["sources"]]
    report["meta"]["problems"] = [f"{name}: {why}" for name, why in cache["problems"]]

    for ip in sorted(cache["entries"], key=_ip_sort_key):
        mac = cache["entries"][ip]
        finding = {"ip": ip, "mac": mac, "note": mac_note(mac)}
        if vendor:
            name = vendor_for(mac)
            finding["vendor"] = name or ("unknown (randomized MAC)"
                                         if is_randomized_mac(mac) else "unknown")
        reportlib.add_finding(report, **finding)

    if not cache["entries"]:
        reportlib.add_error(
            report,
            "no neighbour entries available"
            + ("" if is_root() else " - Android hides the ARP cache from normal apps"),
        )
    elif not scan:
        report["meta"]["hint"] = "run 'netscan arp --scan' to find sleeping devices too"

    randomized = sum(1 for mac in cache["entries"].values() if is_randomized_mac(mac))
    reportlib.finish(
        report,
        entries=len(cache["entries"]),
        sources_used=len(cache["sources"]),
        randomized=randomized,
        sweeps=int(bool(scan)),
    )
    return report


def _gateway(interface_ip: str | None = None) -> str:
    from .ping import get_router_ip

    return get_router_ip(interface_ip or local_ip())


def arp_command(network: str | None = None, scan: bool = False, vendor: bool = False,
                mac_only: bool = False) -> dict:
    """Interactive/menu entry point for the ARP table."""
    report = arp_report(network=network, scan=scan, vendor=vendor)
    return present_arp(report, mac_only=mac_only)


def print_mac_lines(findings) -> None:
    """Bare ``ip<TAB>mac`` rows on stdout, safe to pipe.

    Uses builtin ``print`` on purpose: it bypasses the Rich console, so it keeps
    working when output is quieted (which ``--mac-only`` implies).
    """
    for finding in findings:
        mac = finding.get("mac")
        if mac:
            print(f"{finding['ip']}\t{mac}")


def present_arp(report: dict, mac_only: bool = False) -> dict:
    findings = report.get("findings", [])

    if mac_only:
        print_mac_lines(findings)
        if not findings:
            # Never fail silently: an empty table has a specific cause.
            err("no neighbour entries found")
            _diagnose_to_stderr(report)
        return report

    if is_quiet():
        return report

    if findings:
        table = Table(title=f"ARP / Neighbour Table - {report['target']}",
                      header_style="bold cyan")
        table.add_column("IP", style="cyan")
        table.add_column("MAC", style="yellow")
        table.add_column("NOTE", style="magenta")
        if any("vendor" in finding for finding in findings):
            table.add_column("VENDOR", style="green")
        show_vendor = any("vendor" in finding for finding in findings)
        for finding in findings:
            row = [finding["ip"], finding["mac"], finding.get("note", "")]
            if show_vendor:
                row.append(finding.get("vendor", ""))
            table.add_row(*row)
        console.print(table)
    else:
        warn("No entries in the neighbour cache.")

    summary = report.get("summary", {})
    meta = report.get("meta", {})

    if meta.get("sources"):
        console.print(f"[green]+[/green] Sources: {', '.join(meta['sources'])}")
    if summary.get("randomized"):
        console.print(
            f"[dim]* {summary['randomized']} device(s) use a randomized MAC, so no "
            f"vendor can be identified for them[/dim]"
        )
    if meta.get("hint"):
        console.print(f"[dim]{meta['hint']}[/dim]")

    for problem in meta.get("problems", []):
        console.print(f"[dim]- {problem}[/dim]")

    for error in report.get("errors", []):
        err(error)
        _explain_blocked_cache()

    return report


def _explain_blocked_cache() -> None:
    """Tell the user exactly why there is no MAC data and what unlocks it.

    Written to stderr so that ``--mac-only`` output stays pipeable.
    """
    note("")
    note("MAC addresses need the kernel's ARP cache, which Android hides from "
         "normal apps.")
    note("Options:")
    note("  * run with root:  su -c 'netscan arp --vendor'")
    note("  * pkg install iproute2 net-tools   (adds more cache sources)")
    note("  * netscan local --names   (names work without root)")


def _diagnose_to_stderr(report: dict) -> None:
    """Report which neighbour sources failed, without touching stdout."""
    for problem in report.get("meta", {}).get("problems") or []:
        note(f"- {problem}")
    _explain_blocked_cache()


# --------------------------------------------------------------------------
# SUBNET DISCOVERY
# --------------------------------------------------------------------------


def discover(network: str | None = None, workers: int = 128, timeout: float = 0.8,
             resolve_names: bool = False, vendor: bool = False,
             mac_only: bool = False, show_progress: bool | None = None) -> dict:
    """
    Sweep a local subnet and describe every device that answers.

    MAC addresses come from the neighbour cache, so they appear only where the
    platform lets us read it - the report always says which sources worked.
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
        gateway=_gateway(base_ip),
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

    # The sweep is what fills the kernel's ARP cache, so read it afterwards.
    cache = read_neighbours()
    neighbours = cache["entries"]
    report["meta"]["arp_sources"] = [f"{name} ({count})" for name, count in cache["sources"]]
    report["meta"]["arp_problems"] = [f"{name}: {why}" for name, why in cache["problems"]]

    for ip in sorted(alive, key=_ip_sort_key):
        mac = neighbours.get(ip, "")
        finding = {
            "ip": ip,
            "mac": mac,
            "note": mac_note(mac),
            "hostname": hostname_of(ip) if resolve_names else "",
        }
        if vendor and mac:
            finding["vendor"] = vendor_for(mac)
        reportlib.add_finding(report, **finding)

    wifi = wifi_info()
    report["meta"].update({k: v for k, v in wifi.items() if v is not None})

    macs_found = sum(1 for finding in report["findings"] if finding["mac"])
    reportlib.finish(
        report,
        devices=len(alive),
        routable=len([ip for ip in alive if ip != base_ip]),
        macs_found=macs_found,
        randomized=sum(1 for mac in neighbours.values() if is_randomized_mac(mac)),
    )
    return present(report, mac_only=mac_only)


def present(report: dict, mac_only: bool = False) -> dict:
    findings = report.get("findings", [])

    if mac_only:
        print_mac_lines(findings)
        if not any(finding.get("mac") for finding in findings):
            err("no MAC addresses available - see below")
            _diagnose_to_stderr(report)
        return report

    if is_quiet():
        return report

    table = Table(title=f"Local Network - {report['target']}", header_style="bold cyan")
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="yellow")
    table.add_column("NOTE", style="magenta")
    table.add_column("HOSTNAME", style="green")
    if any(finding.get("vendor") for finding in findings):
        table.add_column("VENDOR", style="green")
    show_vendor = any(finding.get("vendor") for finding in findings)
    for finding in findings:
        row = [
            finding.get("ip", ""),
            finding.get("mac", ""),
            finding.get("note", ""),
            finding.get("hostname", ""),
        ]
        if show_vendor:
            row.append(finding.get("vendor", ""))
        table.add_row(*row)

    console.print(table)

    summary = report.get("summary", {})
    meta = report.get("meta", {})

    console.print(f"[green]+[/green] Devices found: {summary.get('devices', 0)}")
    console.print(f"[green]+[/green] MAC addresses resolved: {summary.get('macs_found', 0)}")
    if summary.get("randomized"):
        console.print(
            f"[dim]* {summary['randomized']} MAC(s) are randomized (Android/iOS privacy "
            f"feature) so they cannot be matched to a vendor[/dim]"
        )
    if meta.get("arp_sources"):
        console.print(f"[dim]ARP source: {', '.join(meta['arp_sources'])}[/dim]")
    if meta.get("gateway"):
        console.print(f"[cyan]+[/cyan] Gateway: {meta['gateway']}")
    if meta.get("ssid"):
        console.print(
            f"[cyan]+[/cyan] Wi-Fi: {meta['ssid']} "
            f"[dim](rssi {meta.get('rssi')}, {meta.get('link_speed_mbps')} Mbps)[/dim]"
        )

    if not summary.get("macs_found"):
        _explain_blocked_cache()

    for error in report.get("errors", []):
        err(error)
    return report


def local_network_scan(network: str | None = None, **kwargs) -> dict:
    """Menu entry point."""
    if not network:
        from core.utils import ask

        answer = ask("Network [blank = auto-detect]", default="")
        network = answer or None
    return discover(network, **kwargs)
