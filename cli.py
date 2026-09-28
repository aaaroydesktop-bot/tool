"""
NetScan command line interface.

Interactive menus are great for exploring, but a network tool also has to be
scriptable: every capability is reachable as a subcommand with machine-readable
output.

    netscan scan 192.168.1.1 --ports top
    netscan scan 10.0.0.0/24 --targets-file hosts.txt --json > scan.json
    netscan whois example.com --format md
    netscan watch 192.168.1.1 --ports web --interval 60
"""

from __future__ import annotations

import argparse
import os
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:  # runnable from any working directory
    sys.path.insert(0, PROJECT_ROOT)

from core import TOOL_NAME, __version__  # noqa: E402
from core import console as console_module  # noqa: E402
from core import report as reportlib  # noqa: E402
from core.console import console, err, info, is_quiet, json_out, ok, warn  # noqa: E402
from core.netutil import clean_targets, format_ports, parse_ports  # noqa: E402

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

#: Reports from these commands are recorded in the history database.
HISTORY_ACTIONS = {
    "scan": "port_scan", "dns": "dns_lookup", "geo": "geoip_lookup",
    "whois": "whois_lookup", "headers": "http_headers",
    "subdomains": "subdomain_scan", "tech": "technology_detection",
    "ping": "ping_test", "traceroute": "traceroute",
    "local": "local_network_scan", "speedtest": "speed_test",
    "sysinfo": "sysinfo",
}


# --------------------------------------------------------------------------
# COMMON OPTIONS
# --------------------------------------------------------------------------


def _add_common(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("output")
    group.add_argument("--json", action="store_true",
                       help="print the raw report as JSON on stdout")
    group.add_argument("-o", "--output", metavar="FILE",
                       help="write the report to FILE")
    group.add_argument("-f", "--format", choices=reportlib.FORMATS, default=None,
                       help="report format (default: from output extension, else json)")
    group.add_argument("--save", action="store_true",
                       help="save the report under reports/ even without -o")
    group.add_argument("--no-history", action="store_true",
                       help="do not record this run in the history database")

    runtime = parser.add_argument_group("runtime")
    runtime.add_argument("--quiet", action="store_true",
                         help="suppress human-readable output")
    runtime.add_argument("--no-color", action="store_true",
                         help="disable ANSI colours")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscan",
        description=f"{TOOL_NAME} {__version__} - Termux networking toolkit",
        epilog="Run 'netscan doctor' to check your Termux setup.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {__version__}")
    _add_common(parser)

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ---- menu -----------------------------------------------------------
    menu = subparsers.add_parser("menu", help="interactive menu (default)")
    _add_common(menu)

    # ---- scan -----------------------------------------------------------
    scan = subparsers.add_parser("scan", help="TCP port scan one or more targets")
    scan.add_argument("targets", nargs="*", help="hosts, IPs, CIDRs or URLs")
    scan.add_argument("-p", "--ports", default="top",
                      help="port spec: top, web, db, all, 1-1024, 22,80,443")
    scan.add_argument("-w", "--workers", type=int, default=None,
                      help="concurrent sockets (default 256)")
    scan.add_argument("-t", "--timeout", type=float, default=None,
                      help="per-port timeout in seconds (default 0.6)")
    scan.add_argument("--targets-file", metavar="FILE",
                      help="read targets from FILE, one per line")
    scan.add_argument("--no-banner", action="store_true",
                      help="skip banner grabbing (faster)")
    scan.add_argument("--watch", type=float, metavar="SECONDS",
                      help="rescan and report changes every SECONDS")
    scan.add_argument("--watch-count", type=int, default=0,
                      help="stop after N watch iterations (0 = until Ctrl+C)")
    scan.add_argument("--show-filtered", action="store_true",
                      help="include filtered ports in the report")
    _add_common(scan)

    # ---- simple single-target lookups -----------------------------------
    for name, help_text, extra in (
        ("dns", "resolve a domain (A/AAAA/PTR/MX/NS/TXT)", None),
        ("geo", "geolocate an IP address", None),
        ("whois", "WHOIS/RDAP registration data", None),
        ("headers", "fetch HTTP response headers + security audit", None),
        ("subdomains", "enumerate subdomains", None),
        ("tech", "fingerprint the technology behind a website", None),
        ("vendor", "resolve a MAC address to its vendor", None),
    ):
        sub = subparsers.add_parser(name, help=help_text)
        sub.add_argument("target", nargs="?", help="target value")
        if name == "subdomains":
            sub.add_argument("--wordlist", metavar="FILE",
                             help="extra wordlist file, one name per line")
            sub.add_argument("-w", "--workers", type=int, default=100)
        if name == "headers":
            sub.add_argument("--no-follow", action="store_true",
                             help="do not follow redirects")
        if name == "vendor":
            sub.add_argument("--offline", action="store_true",
                             help="use only the built-in OUI table")
        sub.add_argument("-t", "--timeout", type=float, default=None)
        _add_common(sub)

    # ---- ping -----------------------------------------------------------
    ping = subparsers.add_parser("ping", help="ping with latency statistics")
    ping.add_argument("target", nargs="?")
    ping.add_argument("-c", "--count", type=int, default=4)
    ping.add_argument("-t", "--timeout", type=float, default=1.0)
    _add_common(ping)

    # ---- traceroute -----------------------------------------------------
    trace = subparsers.add_parser("traceroute", help="trace the path to a host")
    trace.add_argument("target", nargs="?")
    trace.add_argument("-m", "--max-hops", type=int, default=30)
    trace.add_argument("-t", "--timeout", type=float, default=2.0)
    _add_common(trace)

    # ---- local network --------------------------------------------------
    local = subparsers.add_parser("local", help="discover devices on the LAN")
    local.add_argument("-n", "--network", help="subnet in CIDR notation")
    local.add_argument("--names", action="store_true", help="reverse-resolve hostnames")
    local.add_argument("--vendor", action="store_true", help="add MAC vendor names")
    local.add_argument("-w", "--workers", type=int, default=128)
    local.add_argument("-t", "--timeout", type=float, default=0.8)
    _add_common(local)

    # ---- system ---------------------------------------------------------
    sysinfo = subparsers.add_parser("sysinfo", help="CPU/RAM/storage/battery snapshot")
    _add_common(sysinfo)

    monitor = subparsers.add_parser("monitor", help="live system dashboard")
    monitor.add_argument("-i", "--interval", type=float, default=1.0)
    monitor.add_argument("-d", "--duration", type=float, default=None,
                         help="stop after N seconds")
    _add_common(monitor)

    # ---- speed test -----------------------------------------------------
    speed = subparsers.add_parser("speedtest", help="measure internet throughput")
    speed.add_argument("-s", "--size", type=float, default=10,
                       help="download size in MB (default 10)")
    speed.add_argument("--upload", action="store_true", help="also test upload")
    speed.add_argument("-t", "--timeout", type=float, default=60)
    _add_common(speed)

    # ---- history --------------------------------------------------------
    history = subparsers.add_parser("history", help="browse scan history")
    history.add_argument("-l", "--limit", type=int, default=20)
    history.add_argument("-a", "--action", help="filter by action name")
    history.add_argument("--show", type=int, metavar="ID",
                         help="print the stored report for ID")
    history.add_argument("--clear", action="store_true", help="delete all history")
    _add_common(history)

    # ---- plugins --------------------------------------------------------
    plugins = subparsers.add_parser("plugins", help="list or run plugins")
    plugins.add_argument("--run", nargs="?", const="__all__", metavar="NAME",
                         help="run one plugin, or all of them when no NAME is given")
    _add_common(plugins)

    # ---- firewall -------------------------------------------------------
    for name, help_text in (("block", "block an IP"), ("unblock", "unblock an IP")):
        sub = subparsers.add_parser(name, help=help_text)
        sub.add_argument("ip")
        sub.add_argument("--dry-run", action="store_true",
                         help="show the command without applying it")
        _add_common(sub)

    firewall = subparsers.add_parser("firewall", help="inspect firewall rules")
    _add_common(firewall)

    # ---- assistant / diagnostics ----------------------------------------
    ask = subparsers.add_parser("ask", help="turn plain English into a command")
    ask.add_argument("text", nargs="*")
    ask.add_argument("--run", action="store_true", help="execute the planned command")
    _add_common(ask)

    doctor = subparsers.add_parser("doctor", help="check the environment and setup")
    _add_common(doctor)

    return parser


# --------------------------------------------------------------------------
# OUTPUT PLUMBING
# --------------------------------------------------------------------------


def _record(report: dict, args) -> None:
    """Persist a run to the history database unless told not to."""
    if getattr(args, "no_history", False) or getattr(args, "json", False):
        return
    action = HISTORY_ACTIONS.get(getattr(args, "command", ""))
    if not action:
        return
    try:
        from modules.history import save_history

        save_history(action, report.get("target", "?"), report)
    except Exception:
        pass  # history must never break a scan


def emit(report: dict, args) -> None:
    """Send the report to stdout, a file, or both."""
    _record(report, args)

    output = getattr(args, "output", None)
    fmt = getattr(args, "format", None)

    if getattr(args, "json", False) and not output:
        json_out(report)
        return

    if output or getattr(args, "save", False) or fmt:
        if not fmt:
            fmt = "json"
            if output and "." in os.path.basename(output):
                candidate = output.rsplit(".", 1)[-1].lower()
                if candidate in reportlib.FORMATS:
                    fmt = candidate
        try:
            path = reportlib.write(report, fmt=fmt, path=output)
            if not is_quiet():
                ok(f"Report written: {path}")
        except (OSError, ValueError) as exc:
            err(f"could not write report: {exc}")


def _finish(report: dict, args) -> int:
    emit(report, args)
    if report.get("errors") and not report.get("findings"):
        return EXIT_ERROR
    return EXIT_OK


def _targets_from_args(args) -> list[str]:
    targets = list(getattr(args, "targets", []) or [])
    path = getattr(args, "targets_file", None)
    if path:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                targets += handle.read().splitlines()
        except OSError as exc:
            err(f"cannot read targets file: {exc}")
    return clean_targets(targets)


# --------------------------------------------------------------------------
# COMMAND HANDLERS
# --------------------------------------------------------------------------


def cmd_scan(args) -> int:
    from modules.network import (DEFAULT_TIMEOUT, DEFAULT_WORKERS, print_report,
                                 scan_ports)

    targets = _targets_from_args(args)
    if not targets:
        err("scan needs at least one target (or --targets-file)")
        return EXIT_USAGE

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        err(str(exc))
        return EXIT_USAGE

    timeout = args.timeout or DEFAULT_TIMEOUT
    workers = args.workers or DEFAULT_WORKERS

    if not is_quiet():
        info(f"Targets: {len(targets)} | Ports: {format_ports(ports)[:120]} "
             f"({len(ports)} total) | timeout {timeout}s | workers {workers}")

    reports = []
    for target in targets:
        report = scan_ports(target, ports, timeout=timeout, workers=workers,
                            banner=not args.no_banner,
                            keep_filtered=args.show_filtered)
        reports.append(report)
        if not args.json:
            print_report(report, f"Scan - {target}")
            if args.show_filtered:
                filtered = report.get("filtered") or []
                if filtered:
                    warn(f"Filtered (no response): "
                         f"{format_ports(filtered)[:160]}")

    if len(reports) == 1:
        payload = reports[0]
    else:
        payload = reportlib.new_report(
            "port_scan_batch", ", ".join(targets)[:200], targets=len(targets)
        )
        total_open = 0
        for report in reports:
            total_open += report.get("summary", {}).get("open", 0)
            for finding in report.get("findings", []):
                reportlib.add_finding(payload, target=report["target"], **finding)
            for problem in report.get("errors", []):
                reportlib.add_error(payload, f"{report['target']}: {problem}")
        reportlib.finish(payload, targets=len(reports), open=total_open)

    emit(payload, args)

    if args.watch:
        return _watch(args, targets, ports, timeout, workers, payload)

    if payload.get("errors") and not payload.get("findings"):
        return EXIT_ERROR
    return EXIT_OK


def _watch(args, targets, ports, timeout, workers, previous_payload) -> int:
    """Rescan on a timer and report only what changed."""
    from modules.network import diff_reports, print_report, scan_ports

    baseline = {report["target"]: report for report in _iter_reports(previous_payload)}

    if not is_quiet():
        info(f"Watching every {args.watch}s - Ctrl+C to stop.")

    iteration = 0
    try:
        while True:
            time.sleep(args.watch)
            iteration += 1
            for target in targets:
                fresh = scan_ports(target, ports, timeout=timeout, workers=workers)
                changes = diff_reports(baseline.get(target, fresh), fresh)
                baseline[target] = fresh
                changed = changes.get("summary", {}).get("opened", 0) + \
                    changes.get("summary", {}).get("closed", 0)
                if changed:
                    print_report(changes, f"Changes - {target}")
                    emit(changes, args)
                elif not is_quiet():
                    info(f"{target}: no change")
            if args.watch_count and iteration >= args.watch_count:
                return EXIT_OK
    except KeyboardInterrupt:
        if not is_quiet():
            warn("Watch stopped.")
        return EXIT_OK


def _iter_reports(payload: dict):
    """Yield per-target reports out of a possibly-batched payload."""
    if payload.get("kind") != "port_scan_batch":
        yield payload
        return
    grouped: dict[str, dict] = {}
    for finding in payload.get("findings", []):
        target = finding.get("target", "?")
        grouped.setdefault(target, reportlib.new_report("port_scan", target))
        grouped[target]["findings"].append(
            {key: value for key, value in finding.items() if key != "target"}
        )
    yield from grouped.values()


def cmd_dns(args) -> int:
    from modules.network import dns_lookup

    return _finish(dns_lookup(args.target), args)


def cmd_geo(args) -> int:
    from modules.network import geo_lookup

    return _finish(geo_lookup(args.target), args)


def cmd_whois(args) -> int:
    from modules.osint import whois_lookup

    return _finish(whois_lookup(args.target), args)


def cmd_headers(args) -> int:
    from modules.network import http_headers

    return _finish(http_headers(args.target, timeout=args.timeout or 10,
                                follow=not args.no_follow), args)


def cmd_subdomains(args) -> int:
    from modules.network import subdomain_scan

    wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as handle:
                wordlist = [line.strip() for line in handle if line.strip()]
        except OSError as exc:
            err(f"cannot read wordlist: {exc}")
            return EXIT_ERROR
    return _finish(subdomain_scan(args.target, wordlist=wordlist, workers=args.workers), args)


def cmd_tech(args) -> int:
    from modules.network import detect_technology

    return _finish(detect_technology(args.target, timeout=args.timeout or 10), args)


def cmd_vendor(args) -> int:
    from modules.network import vendor_lookup

    return _finish(vendor_lookup(args.target, online=not args.offline), args)


def cmd_ping(args) -> int:
    from modules.network import ping_test

    return _finish(ping_test(args.target, count=args.count, timeout=args.timeout), args)


def cmd_traceroute(args) -> int:
    from modules.network import traceroute

    return _finish(traceroute(args.target, max_hops=args.max_hops,
                              timeout=args.timeout), args)


def cmd_local(args) -> int:
    from modules.network import local_scan

    return _finish(local_scan(args.network, workers=args.workers,
                              timeout=args.timeout, resolve_names=args.names,
                              vendor=args.vendor), args)


def cmd_sysinfo(args) -> int:
    from modules.monitoring import system_info

    return _finish(system_info(), args)


def cmd_monitor(args) -> int:
    from modules.monitoring import system_monitor

    system_monitor(interval=args.interval, duration=args.duration)
    return EXIT_OK


def cmd_speedtest(args) -> int:
    from modules.network import speed_test

    return _finish(speed_test(size_mb=args.size, upload=args.upload,
                              timeout=args.timeout), args)


def cmd_history(args) -> int:
    from modules.history import clear, load_result, records, show_history, stats

    if args.clear:
        if args.json:
            json_out({"deleted": clear()})
        else:
            ok(f"Deleted {clear()} history entries.")
        return EXIT_OK

    if args.show is not None:
        report = load_result(args.show)
        if not report:
            err(f"no stored report for entry {args.show}")
            return EXIT_ERROR
        if args.json:
            json_out(report)
        else:
            console.print_json(data=report)
        return EXIT_OK

    rows = records(limit=args.limit, action=args.action)
    if args.json:
        json_out({"stats": stats(), "entries": rows})
        return EXIT_OK

    show_history(args.limit)
    return EXIT_OK


def cmd_plugins(args) -> int:
    from modules.plugins import discover, run, run_all

    if args.run is None:
        listed = discover()
        if args.json:
            json_out({"plugins": listed})
        return EXIT_OK

    if args.run == "__all__":
        results = run_all()
    else:
        results = [run(args.run)]

    for result in results:
        emit(result, args)
    return EXIT_OK if all(not r["errors"] for r in results) else EXIT_ERROR


def cmd_block(args) -> int:
    from modules.firewall import block_ip

    return _finish(block_ip(args.ip, dry_run=args.dry_run), args)


def cmd_unblock(args) -> int:
    from modules.firewall import unblock_ip

    return _finish(unblock_ip(args.ip, dry_run=args.dry_run), args)


def cmd_firewall(args) -> int:
    from modules.firewall import list_rules

    report = list_rules()
    if not args.json and not is_quiet():
        table = report.get("findings", [])
        for finding in table:
            console.print(f"[dim]{finding.get('rule', '')}[/dim]")
        if not table:
            warn("No rules matched.")
    return _finish(report, args)


def cmd_ask(args) -> int:
    from modules.ai import ai_assistant

    text = " ".join(args.text) if args.text else None
    result = ai_assistant(text, execute=False)

    if args.json:
        json_out(result)
        return EXIT_OK if result["argv"] else EXIT_ERROR

    if args.run and result["argv"]:
        return main(result["argv"])
    return EXIT_OK if result["argv"] else EXIT_ERROR


def cmd_doctor(args) -> int:
    from core import checker

    report = checker.doctor()
    if args.json:
        json_out(report)
        return EXIT_OK

    from rich.table import Table

    table = Table(title=f"{TOOL_NAME} doctor", header_style="bold cyan")
    table.add_column("CHECK", style="cyan")
    table.add_column("STATUS", style="green")
    table.add_column("DETAIL", overflow="fold")
    for check in report["findings"]:
        status = str(check.get("status", ""))
        colour = {"ok": "green", "warn": "yellow", "fail": "red"}.get(status, "white")
        table.add_row(
            str(check.get("check", "")),
            f"[{colour}]{status}[/{colour}]",
            str(check.get("detail", "")),
        )
    console.print(table)
    console.print(f"[dim]History entries: {report['summary'].get('history_entries', 0)}[/dim]")

    if not is_quiet():
        from core import checker as _checker

        missing = report["summary"].get("missing_optional") or []
        if missing:
            packages = " ".join(_checker.pip_name(name) for name in missing)
            console.print(
                f"\n[yellow]Optional modules missing:[/yellow] {', '.join(missing)}"
                f"\n[dim]Install with: pip install {packages}[/dim]"
            )
    return EXIT_OK if report["summary"].get("healthy") else EXIT_ERROR


def cmd_menu(args) -> int:
    import main

    return main.run_menu()


HANDLERS = {
    "menu": cmd_menu, "scan": cmd_scan, "dns": cmd_dns, "geo": cmd_geo,
    "whois": cmd_whois, "headers": cmd_headers, "subdomains": cmd_subdomains,
    "tech": cmd_tech, "vendor": cmd_vendor, "ping": cmd_ping,
    "traceroute": cmd_traceroute, "local": cmd_local, "sysinfo": cmd_sysinfo,
    "monitor": cmd_monitor, "speedtest": cmd_speedtest, "history": cmd_history,
    "plugins": cmd_plugins, "block": cmd_block, "unblock": cmd_unblock,
    "firewall": cmd_firewall, "ask": cmd_ask, "doctor": cmd_doctor,
}


# --------------------------------------------------------------------------
# ENTRY POINT
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # --json promises a machine-readable stdout, so human chatter is silenced
    # for the whole run. Errors still reach stderr.
    console_module.configure(
        quiet=bool(getattr(args, "quiet", False) or getattr(args, "json", False)),
        color=False if getattr(args, "no_color", False) else None,
    )

    if not args.command:
        return cmd_menu(args)

    handler = HANDLERS.get(args.command)
    if not handler:
        parser.print_help()
        return EXIT_USAGE

    try:
        return handler(args)
    except KeyboardInterrupt:
        if not is_quiet():
            warn("Interrupted.")
        return 130
    except Exception as exc:  # keep the CLI honest instead of dumping a trace
        err(f"{type(exc).__name__}: {exc}")
        if os.environ.get("NETSCAN_DEBUG"):
            raise
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
