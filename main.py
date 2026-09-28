#!/usr/bin/env python3
"""
NetScan entry point.

Two ways in, one codebase:

* ``python main.py``            -> interactive menu
* ``python main.py <command>``  -> non-interactive CLI (see ``--help``)
"""

from __future__ import annotations

import os
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:  # importable from any working directory
    sys.path.insert(0, PROJECT_ROOT)

from core import TOOL_NAME, VERSION_LABEL, checker, report as reportlib  # noqa: E402
from core.banner import banner  # noqa: E402
from core.console import console, err, info, is_quiet, ok, warn  # noqa: E402
from core.menu import render  # noqa: E402
from core.netutil import clean_targets, parse_ports  # noqa: E402
from core.utils import ask, pause  # noqa: E402

#: The interactive session remembers the newest report so it can be exported.
LAST: dict = {"report": None}


# --------------------------------------------------------------------------
# SHARED HELPERS
# --------------------------------------------------------------------------


def _remember(result) -> None:
    if isinstance(result, dict) and result.get("kind"):
        LAST["report"] = result


def _ask_target(prompt: str = "Target IP/Domain") -> str:
    return ask(prompt).strip()


def _custom_scan() -> dict:
    from modules.network import print_report, scan_ports

    target = _ask_target()
    spec = ask("Ports [top|web|db|all|1-1024|22,80,443]", default="top")
    try:
        ports = parse_ports(spec)
    except ValueError as exc:
        err(str(exc))
        return {}

    info(f"Scanning {len(ports)} ports on {target}...")
    report = scan_ports(target, ports)
    print_report(report, f"Custom Scan - {target}")
    return report


def _batch_scan() -> dict:
    from modules.network import print_report, scan_ports

    raw = ask("Targets (comma separated, or a file path)")
    candidates = raw.splitlines()
    if os.path.isfile(raw.strip()):
        with open(raw.strip(), "r", encoding="utf-8", errors="ignore") as handle:
            candidates = handle.read().splitlines()
    else:
        candidates = raw.replace(",", " ").split()

    targets = clean_targets(candidates)
    if not targets:
        warn("No valid targets.")
        return {}

    spec = ask("Ports [top|web|db|1-1024]", default="top")
    try:
        ports = parse_ports(spec)
    except ValueError as exc:
        err(str(exc))
        return {}

    combined = reportlib.new_report("port_scan_batch", ", ".join(targets)[:200],
                                    targets=len(targets))
    total_open = 0

    for target in targets:
        report = scan_ports(target, ports)
        print_report(report, f"Scan - {target}")
        total_open += report.get("summary", {}).get("open", 0)
        for finding in report.get("findings", []):
            reportlib.add_finding(combined, target=target, **finding)

    reportlib.finish(combined, targets=len(targets), open=total_open)
    path = reportlib.write(combined, fmt="md")
    ok(f"Batch report saved: {path}")
    return combined


def _watch_host() -> dict:
    from modules.network import diff_reports, print_report, scan_ports

    target = _ask_target()
    spec = ask("Ports [top|web|db|1-1024]", default="top")
    try:
        ports = parse_ports(spec)
    except ValueError as exc:
        err(str(exc))
        return {}

    try:
        interval = max(5.0, float(ask("Interval in seconds", default="30")))
    except ValueError:
        interval = 30.0

    baseline = scan_ports(target, ports)
    print_report(baseline, f"Baseline - {target}")
    info(f"Watching every {interval:.0f}s. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(interval)
            fresh = scan_ports(target, ports)
            changes = diff_reports(baseline, fresh)
            opened = changes["summary"].get("opened", 0)
            closed = changes["summary"].get("closed", 0)
            if opened or closed:
                print_report(changes, f"Changes - {target}")
                reportlib.write(changes, fmt="json")
            else:
                info(f"{target}: no change ({fresh['summary'].get('open', 0)} open ports)")
            baseline = fresh
    except KeyboardInterrupt:
        warn("Watch stopped.")
        return baseline


def _export_last() -> dict:
    if not LAST["report"]:
        warn("No report in this session yet - run a scan first.")
        return {}
    fmt = ask("Format [json|md|html|csv|txt]", default="json").strip().lower()
    try:
        path = reportlib.write(LAST["report"], fmt=fmt)
    except ValueError as exc:
        err(str(exc))
        return {}
    ok(f"Saved: {path}")
    return LAST["report"]


def _list_reports() -> dict:
    from rich.table import Table

    files = reportlib.latest(limit=15)
    if not files:
        warn("No reports saved yet.")
        return {}

    table = Table(title="Recent Reports", header_style="bold cyan")
    table.add_column("FILE", style="green", overflow="fold")
    table.add_column("SIZE", style="cyan", justify="right")
    table.add_column("WHEN", style="dim")
    for path in files:
        try:
            stat = os.stat(path)
        except OSError:
            continue
        table.add_row(
            os.path.relpath(path),
            f"{stat.st_size / 1024:.1f} KB",
            time.strftime("%Y-%m-%d %H:%M", time.localtime(stat.st_mtime)),
        )
    console.print(table)
    return {}


def _show_history() -> dict:
    from modules.history import show_history

    show_history()
    return {}


def _sysinfo() -> dict:
    from modules.monitoring import render as render_sysinfo
    from modules.monitoring import system_info

    console.print(render_sysinfo())
    return system_info()


def _arp_table() -> dict:
    from modules.network import arp_command

    return arp_command(scan=True, vendor=True)


def _tls_audit() -> dict:
    from modules.network import tls_audit

    return tls_audit()


def _firewall_status() -> dict:
    from modules.firewall import list_rules

    report = list_rules()
    for finding in report.get("findings", []):
        console.print(f"[dim]{finding.get('rule', '')}[/dim]")
    if not report.get("findings"):
        warn("No matching rules - or you need root to read them.")
    for problem in report.get("errors", []):
        warn(problem)
    return report


def _doctor() -> dict:
    import cli

    cli.main(["doctor"])
    return {}


def _speedtest() -> dict:
    from modules.network import speed_test

    return speed_test()


def _plugins() -> dict:
    from modules.plugins import load_plugins

    load_plugins()
    return {}


def _block_ip() -> dict:
    from modules.firewall import block_ip

    return block_ip()


def _unblock_ip() -> dict:
    from modules.firewall import unblock_ip

    return unblock_ip()


def _monitor() -> dict:
    from modules.monitoring import system_monitor

    system_monitor()
    return {}


# --------------------------------------------------------------------------
# MENU REGISTRY  (single source of truth for display *and* dispatch)
# --------------------------------------------------------------------------


def build_registry() -> list[tuple[str, list[tuple[str, str, callable]]]]:
    from modules import ai, network, osint

    return [
        ("NETWORK SCANNING", [
            ("Smart Port Scan (top ports)", network.auto_port_scan),
            ("Fast Port Scan (1-1024)", lambda: network.port_scan(None, 1, 1024)),
            ("Full Port Scan (all 65535)", lambda: network.full_port_scan()),
            ("Custom Port Scan (range / list)", _custom_scan),
            ("Batch Scan (multiple hosts)", _batch_scan),
            ("Watch A Host For Changes", _watch_host),
            ("Ping Test", network.ping_test),
            ("Traceroute", network.traceroute),
        ]),
        ("NETWORK INFORMATION", [
            ("DNS Lookup", network.dns_lookup),
            ("GeoIP Lookup", network.geo_lookup),
            ("HTTP Header Grabber", network.http_headers),
            ("Subdomain Scanner", network.subdomain_scan),
            ("WHOIS Lookup", osint.whois_lookup),
            ("Vendor Detection", network.vendor_lookup),
            ("Technology Detection", network.detect_technology),
            ("TLS / Certificate Audit", _tls_audit),
        ]),
        ("LOCAL NETWORK", [
            ("Local Network Scan", network.local_network_scan),
            ("ARP Table (IP + MAC)", _arp_table),
            ("Firewall Status", _firewall_status),
            ("Block IP", _block_ip),
            ("Unblock IP", _unblock_ip),
        ]),
        ("SYSTEM", [
            ("Live System Monitor", _monitor),
            ("System Info Snapshot", _sysinfo),
            ("Internet Speed Test", _speedtest),
        ]),
        ("TOOLS", [
            ("AI Assistant (text -> command)", ai.ai_assistant),
            ("Plugins", _plugins),
            ("Scan History", _show_history),
            ("Export Last Report", _export_last),
            ("Recent Report Files", _list_reports),
            ("Doctor / Setup Check", _doctor),
        ]),
    ]


def _numbered(registry):
    """Flatten the registry into ``{number: (label, handler)}``."""
    entries: dict[int, tuple[str, callable]] = {}
    display: list[tuple[str, list[tuple[str, str]]]] = []
    counter = 0

    for title, items in registry:
        shown: list[tuple[str, str]] = []
        for label, handler in items:
            counter += 1
            entries[counter] = (label, handler)
            shown.append((str(counter), label))
        display.append((title, shown))

    return entries, display


# --------------------------------------------------------------------------
# INTERACTIVE LOOP
# --------------------------------------------------------------------------


def run_menu() -> int:
    """Interactive session.  Returns a shell exit code."""
    checker.check_modules()

    from modules.history import init_db

    init_db()

    if not is_quiet():
        console.print(f"[dim]{TOOL_NAME} {VERSION_LABEL} | interactive mode[/dim]")

    while True:
        entries, display = _numbered(build_registry())

        try:
            banner()
            render(display, columns=2)
            console.print()

            if LAST["report"]:
                summary = LAST["report"].get("summary", {})
                console.print(
                    f"[dim]last: {LAST['report'].get('kind')} on "
                    f"{LAST['report'].get('target')} "
                    f"({summary.get('open', '?')} results)[/dim]\n"
                )

            console.print("[bold red][0] Exit[/bold red]\n")

            choice = ask("Select Option").strip()

            if choice in ("0", "q", "exit", "quit"):
                console.print("\n[bold red]Exiting NetScan...[/bold red]")
                console.print("[bold cyan]Goodbye![/bold cyan]\n")
                return 0

            if not choice:
                continue

            if int(choice) not in entries:
                warn("Invalid option.")
                pause()
                continue

            label, handler = entries[int(choice)]
            console.print(f"\n[yellow][*][/yellow] {label}...\n")
            time.sleep(0.2)

            result = handler()
            _remember(result)
            pause()

        except KeyboardInterrupt:
            console.print("\n[bold red]Interrupted By User[/bold red]")
            return 130

        except ValueError:
            warn("Please enter a number.")
            pause()

        except Exception as exc:
            console.print_exception()
            err(f"{type(exc).__name__}: {exc}")
            try:
                pause()
            except KeyboardInterrupt:
                return 130


def main(argv: list[str] | None = None) -> int:
    """Dispatch to the CLI (which falls back to the interactive menu)."""
    import cli

    return cli.main(sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":
    sys.exit(main())
