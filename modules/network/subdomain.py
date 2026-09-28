"""Subdomain enumeration with wildcard-DNS awareness."""

from __future__ import annotations

import concurrent.futures
import random
import socket
import string

from rich.table import Table

from core import report as reportlib
from core.console import console, err, info, is_quiet
from core.netutil import parse_target

#: Built-in wordlist - no internet needed, keeps the tool usable offline.
WORDLIST = [
    "www", "mail", "smtp", "pop", "imap", "webmail", "mx", "email", "ns1", "ns2",
    "dns", "ftp", "sftp", "api", "app", "apps", "dev", "develop", "staging",
    "stage", "test", "testing", "qa", "uat", "demo", "beta", "alpha", "preview",
    "admin", "panel", "portal", "dashboard", "manage", "internal", "intranet",
    "vpn", "remote", "rdp", "ssh", "gateway", "gw", "router", "firewall", "proxy",
    "cdn", "static", "assets", "img", "images", "media", "video", "files", "download",
    "blog", "news", "forum", "shop", "store", "cart", "pay", "payment", "checkout",
    "auth", "login", "sso", "oauth", "id", "account", "my", "support", "help",
    "status", "monitor", "metrics", "grafana", "prometheus", "kibana", "jenkins",
    "git", "gitlab", "github", "bitbucket", "ci", "build", "deploy", "docker",
    "db", "database", "mysql", "postgres", "mongo", "redis", "cache", "queue",
    "mq", "kafka", "elastic", "search", "logs", "backup", "sql", "old", "new",
    "v1", "v2", "mobile", "m", "wap", "ns", "whois", "mail2", "lists", "wiki",
]


def _resolve(host: str, timeout: float) -> str | None:
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None
    finally:
        socket.setdefaulttimeout(previous)


def wildcard_addresses(domain: str) -> set[str]:
    """Detect wildcard DNS so random names do not create false positives."""
    found = set()
    token = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    for candidate in (f"{token}.{domain}", f"{token}-wildcard-check.{domain}"):
        ip = _resolve(candidate, 3)
        if ip:
            found.add(ip)
    return found


def scan(domain: str | None = None, wordlist=None, workers: int = 100,
         timeout: float = 3, show_progress: bool | None = None) -> dict:
    """Enumerate subdomains of ``domain`` and return a report dict."""
    if not domain:
        from core.utils import ask

        domain = ask("Domain")

    domain, _ = parse_target(domain)
    words = [w.strip() for w in (wordlist or WORDLIST) if str(w).strip()]

    report = reportlib.new_report(
        "subdomain_scan", domain, candidates=len(words), workers=workers
    )
    info(f"Enumerating {len(words)} candidates under {domain}...")

    wildcard = wildcard_addresses(domain)
    if wildcard:
        report["meta"]["wildcard_dns"] = ", ".join(sorted(wildcard))
        info(f"Wildcard DNS detected ({', '.join(sorted(wildcard))}) - filtering.")

    found: dict[str, str] = {}

    def worker(word: str):
        host = f"{word}.{domain}"
        ip = _resolve(host, timeout)
        return (host, ip) if ip else None

    if show_progress is None:
        show_progress = not is_quiet() and len(words) > 40

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    try:
        if show_progress:
            from rich.progress import Progress

            with Progress() as progress:
                task = progress.add_task("[green]Resolving...", total=len(words))
                for result in pool.map(worker, words, chunksize=8):
                    progress.update(task, advance=1)
                    if result:
                        found[result[0]] = result[1]
        else:
            for result in pool.map(worker, words, chunksize=8):
                if result:
                    found[result[0]] = result[1]
    finally:
        pool.shutdown(wait=True)

    for host in sorted(found):
        finding = {"host": host, "ip": found[host]}
        if found[host] in wildcard:
            finding["note"] = "wildcard"
        reportlib.add_finding(report, **finding)

    reportlib.finish(report, found=len(found), wildcard=bool(wildcard))
    return _present(report)


def _present(report: dict) -> dict:
    if is_quiet():
        return report
    findings = report.get("findings", [])
    if findings:
        table = Table(title=f"Subdomains - {report['target']}", header_style="bold cyan")
        table.add_column("HOST", style="cyan")
        table.add_column("IP", style="green")
        table.add_column("NOTE", style="yellow")
        for finding in findings:
            table.add_row(finding["host"], finding["ip"], finding.get("note", ""))
        console.print(table)
    else:
        console.print("[yellow][!][/yellow] No subdomains resolved.")
    for error in report.get("errors", []):
        err(error)
    return report
