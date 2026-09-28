"""
Firewall rules.

On Termux this needs root *and* a kernel with iptables/nft support, which is not
guaranteed.  So: validate input, detect the backend, support ``dry_run`` and
always explain what happened instead of failing silently.
"""

from __future__ import annotations

import platform
import shutil
import subprocess

from rich.table import Table

from core import report as reportlib
from core.console import console, err, info, is_quiet, warn
from core.environment import is_root
from core.netutil import is_ip

WINDOWS = platform.system().lower().startswith("win")
CHAIN = "INPUT"
RULE_PREFIX = "NETSCAN_BLOCK"


def backend() -> str | None:
    """Which firewall tool is usable here."""
    if WINDOWS:
        return "netsh" if shutil.which("netsh") else None
    for candidate in ("iptables", "nft"):
        if shutil.which(candidate):
            return candidate
    return None


def available() -> tuple[bool, str]:
    """Return ``(usable, reason_if_not)``."""
    tool = backend()
    if not tool:
        return False, "no iptables/nft/netsh binary found"
    if tool != "netsh" and not is_root():
        return False, "root is required to modify firewall rules on Termux/Linux"
    return True, tool


def _run(command: list[str], dry_run: bool) -> tuple[bool, str]:
    rendered = " ".join(command)
    if dry_run:
        return True, rendered
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"{rendered} -> {exc}"
    if completed.returncode != 0:
        return False, f"{rendered} -> {completed.stderr.strip() or completed.returncode}"
    return True, rendered


def list_rules() -> dict:
    """Show current rules for the detected backend."""
    report = reportlib.new_report("firewall_status", "local", backend=backend())
    usable, reason = available()
    if not usable:
        reportlib.add_error(report, reason)
        reportlib.finish(report, rules=0, usable=False)
        return report

    tool = backend()
    command = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"] \
        if tool == "netsh" else [tool, "-L", "-n"]
    try:
        output = subprocess.run(command, capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        reportlib.add_error(report, str(exc))
        reportlib.finish(report, rules=0, usable=True)
        return report

    count = 0
    for line in output.splitlines():
        text = line.strip()
        if not text:
            continue
        if RULE_PREFIX in text or "-A INPUT" in text or "INPUT" in text:
            reportlib.add_finding(report, rule=text[:160])
            count += 1
        if count >= 200:
            break

    reportlib.finish(report, rules=count, usable=True)
    return report


def block(ip: str, dry_run: bool = False) -> dict:
    """Block inbound traffic from ``ip``."""
    report = reportlib.new_report("firewall_block", str(ip), dry_run=dry_run)
    if not is_ip(str(ip)):
        reportlib.add_error(report, f"not a valid IP address: {ip!r}")
        reportlib.finish(report, applied=False)
        return report

    usable, reason = available()
    if not usable:
        reportlib.add_error(report, reason)
        reportlib.finish(report, applied=False)
        return _present(report)

    tool = backend()
    if tool == "netsh":
        command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={RULE_PREFIX}_{ip}", "dir=in", "action=block", f"remoteip={ip}",
        ]
    elif tool == "nft":
        command = ["nft", "add", "rule", "inet", "filter", "input",
                   "ip", "saddr", ip, "drop"]
    else:
        command = [tool, "-A", CHAIN, "-s", ip, "-j", "DROP"]

    ok, detail = _run(command, dry_run)
    if not ok:
        reportlib.add_error(report, detail)
    else:
        reportlib.add_finding(report, ip=ip, rule=detail)

    reportlib.finish(report, applied=ok, dry_run=dry_run, backend=tool)
    return _present(report)


def unblock(ip: str, dry_run: bool = False) -> dict:
    """Remove the block rule for ``ip``."""
    report = reportlib.new_report("firewall_unblock", str(ip), dry_run=dry_run)
    if not is_ip(str(ip)):
        reportlib.add_error(report, f"not a valid IP address: {ip!r}")
        reportlib.finish(report, applied=False)
        return report

    usable, reason = available()
    if not usable:
        reportlib.add_error(report, reason)
        reportlib.finish(report, applied=False)
        return _present(report)

    tool = backend()
    if tool == "netsh":
        command = ["netsh", "advfirewall", "firewall", "delete", "rule",
                   f"name={RULE_PREFIX}_{ip}"]
        attempts = [command]
    elif tool == "nft":
        attempts = [["nft", "-a", "list", "chain", "inet", "filter", "input"]]
    else:
        attempts = [[tool, "-D", CHAIN, "-s", ip, "-j", "DROP"]]

    ok, detail = False, ""
    for command in attempts:
        ok, detail = _run(command, dry_run)
        if ok:
            break
    if not ok:
        reportlib.add_error(report, detail)
    else:
        reportlib.add_finding(report, ip=ip, rule=detail)

    reportlib.finish(report, applied=ok, dry_run=dry_run, backend=tool)
    return _present(report)


# --------------------------------------------------------------------------
# INTERACTIVE WRAPPERS
# --------------------------------------------------------------------------


def block_ip(ip: str | None = None, dry_run: bool = False) -> dict:
    if not ip:
        from core.utils import ask

        ip = ask("IP To Block")
    info(f"Blocking {ip}...")
    return block(ip, dry_run=dry_run)


def unblock_ip(ip: str | None = None, dry_run: bool = False) -> dict:
    if not ip:
        from core.utils import ask

        ip = ask("IP To Unblock")
    info(f"Unblocking {ip}...")
    return unblock(ip, dry_run=dry_run)


def _present(report: dict) -> dict:
    if is_quiet():
        return report

    if report.get("findings"):
        table = Table(title=f"Firewall - {report['kind']}", header_style="bold cyan")
        table.add_column("IP", style="cyan")
        table.add_column("RULE", style="green", overflow="fold")
        for finding in report["findings"]:
            table.add_row(str(finding.get("ip", "")), str(finding.get("rule", "")))
        console.print(table)

    summary = report.get("summary", {})
    if summary.get("dry_run"):
        warn("Dry run - nothing was changed. Re-run without --dry-run to apply.")
    if summary.get("backend") and report["kind"] == "firewall_status":
        console.print(f"[cyan]+[/cyan] Backend: {summary['backend']}")

    for error in report.get("errors", []):
        if "root is required" in str(error):
            err("root required - try: su -c 'netscan block <ip>'")
        else:
            err(error)
    return report
