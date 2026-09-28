"""
Natural language helper.

This is a deterministic planner, not a language model: it maps plain English
phrases onto real ``netscan`` subcommands so the tool can be driven by text
without guessing at network behaviour.
"""

from __future__ import annotations

import re
import shlex

from rich.table import Table

from core.console import console, is_quiet

_TARGET_RE = re.compile(
    r"((?:\d{1,3}\.){3}\d{1,3}"
    r"|(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}"
    r"|(?:https?://)?[a-z0-9.\-]+\.[a-z]{2,}(?:/\S*)?)",
    re.I,
)
_PORT_SPEC_RE = re.compile(r"\b(ports?\s+(\S+)|(\d+\s*-\s*\d+))\b", re.I)


def _target(text: str) -> str | None:
    match = _TARGET_RE.search(text)
    return match.group(1) if match else None


def _ports(text: str) -> str | None:
    match = _PORT_SPEC_RE.search(text)
    if not match:
        return None
    return re.sub(r"^ports?\s+", "", match.group(1), flags=re.I).strip()


#: (pattern, subcommand, needs_target)
RULES = [
    (r"\b(local|lan|wifi|home network|arp|devices?)\b", "local", False),
    (r"\b(speed ?test|bandwidth|download speed|throughput)\b", "speedtest", False),
    (r"\b(sysinfo|system info|device info|battery|cpu|ram|memory)\b", "sysinfo", False),
    (r"\b(trace|traceroute|path to|hops?)\b", "traceroute", True),
    (r"\b(ping|latency|is it up|alive|reachable)\b", "ping", True),
    (r"\b(whois|registrar|domain owner|registration)\b", "whois", True),
    (r"\b(subdomain|sub-?domains|enum)\b", "subdomains", True),
    (r"\b(headers?|http head)\b", "headers", True),
    (r"\b(tech|technology|stack|what runs|fingerprint|cms)\b", "tech", True),
    (r"\b(geo|geolocation|where is|location|country|isp)\b", "geo", True),
    (r"\b(dns|resolve|nameserver|a record|mx)\b", "dns", True),
    (r"\b(mac|vendor|oui|manufacturer)\b", "vendor", True),
    (r"\b(history|past scans|previous)\b", "history", False),
    (r"\b(plugin)s?\b", "plugins", False),
    (r"\b(doctors?|check|health|setup)\b", "doctor", False),
    (r"\b(full|all ports|65535|every port)\b", "scan", True),
    (r"\b(scan|port scan|open ports?|nmap)\b", "scan", True),
]


def plan(text: str) -> dict:
    """
    Turn a sentence into a command plan.

    Returns ``{"argv": [...], "explanation": str, "confidence": "high|low"}``.
    """
    text = (text or "").strip()
    lowered = text.lower()

    for pattern, command, needs_target in RULES:
        if not re.search(pattern, lowered):
            continue

        target = _target(text)
        if needs_target and not target:
            return {
                "argv": [],
                "explanation": f"'{command}' needs a target - say something like "
                               f"\"{command} example.com\".",
                "confidence": "low",
                "command": command,
            }

        argv = [command]
        if needs_target:
            argv.append(target)

        if command == "scan":
            spec = _ports(text)
            if spec:
                argv += ["--ports", spec]
            elif re.search(r"\b(full|all ports|65535)\b", lowered):
                argv += ["--ports", "all"]

        explanation = f"maps to: netscan {' '.join(shlex.quote(a) for a in argv)}"
        return {"argv": argv, "explanation": explanation, "confidence": "high",
                "command": command}

    return {
        "argv": [],
        "explanation": "could not map that to a command. Try: "
                       "\"scan 192.168.1.1\", \"whois example.com\", \"local devices\".",
        "confidence": "low",
        "command": None,
    }


def ai_assistant(text: str | None = None, execute: bool = False) -> dict:
    """Plan (and optionally run) a command from free text."""
    if not text:
        from core.utils import ask

        text = ask("Ask AI")

    result = plan(text)

    if not is_quiet():
        table = Table(title="Command Planner", header_style="bold cyan")
        table.add_column("FIELD", style="cyan")
        table.add_column("VALUE", style="green", overflow="fold")
        table.add_row("input", text)
        table.add_row("command", result.get("command") or "-")
        table.add_row("argv", " ".join(result["argv"]) or "-")
        table.add_row("explanation", result["explanation"])
        table.add_row("confidence", result["confidence"])
        console.print(table)

    if execute and result["argv"]:
        import cli

        result["exit_code"] = cli.main(result["argv"])

    return result
