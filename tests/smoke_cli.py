"""
End-to-end CLI smoke test.

Runs the real command line against loopback, so it exercises argument parsing,
the scanning engine, report writing and history — without needing a network or
a Rich install.

    python tests/smoke_cli.py
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tests import rich_stub  # noqa: E402

STUB = rich_stub.install()

import cli  # noqa: E402
from core import report as reportlib  # noqa: E402

PASSED: list[str] = []
FAILED: list[str] = []


def run(argv: list[str], expect: int = 0) -> str:
    """Invoke the CLI, capturing stdout, and assert the exit code."""
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        try:
            code = cli.main(argv)
        except SystemExit as exc:
            code = int(exc.code or 0)
    name = "netscan " + " ".join(argv)
    output = buffer.getvalue()
    if code == expect:
        PASSED.append(name)
    else:
        FAILED.append(f"{name} -> exit {code}, expected {expect}")
    return output


def main() -> int:
    print(f"Rich available: {not STUB} (stub={'yes' if STUB else 'no'})\n")

    # --- help / version -------------------------------------------------
    help_text = run(["--help"])
    for command in ("scan", "dns", "local", "doctor", "history"):
        if command not in help_text:
            FAILED.append(f"--help does not mention '{command}'")
    run(["--version"])

    # --- per-command help ----------------------------------------------
    for command in ("scan", "headers", "subdomains", "history", "plugins", "ask"):
        run([command, "--help"])

    # --- real scan against loopback ------------------------------------
    payload = run(["scan", "127.0.0.1", "--ports", "1-64", "--json", "--no-banner"])
    try:
        report = json.loads(payload)
    except ValueError:
        FAILED.append("scan --json did not produce valid JSON")
        report = {}
    else:
        for key in ("kind", "target", "findings", "summary"):
            if key not in report:
                FAILED.append(f"scan JSON missing '{key}'")
        if report.get("target") != "127.0.0.1":
            FAILED.append("scan JSON target mismatch")
        if "open" not in report.get("summary", {}):
            FAILED.append("scan JSON missing summary.open")

    # --- scan with a bad port spec should be a usage error --------------
    run(["scan", "127.0.0.1", "--ports", "definitely-not-ports", "--json"],
        expect=cli.EXIT_USAGE)

    # --- report file output --------------------------------------------
    directory = os.path.join(ROOT, "reports")
    for fmt in ("md", "html", "csv", "txt"):
        target = os.path.join(directory, f"smoke_report.{fmt}")
        run(["scan", "127.0.0.1", "--ports", "1-8", "-o", target, "--quiet"])
        if not os.path.exists(target):
            FAILED.append(f"report not written: {target}")
        elif os.path.getsize(target) == 0:
            FAILED.append(f"report is empty: {target}")
        else:
            PASSED.append(f"report written: {os.path.basename(target)}")

    # --- local network, ping, dns --------------------------------------
    run(["ping", "127.0.0.1", "-c", "1", "--timeout", "1", "--json"])
    run(["dns", "localhost", "--json"])
    run(["vendor", "B8:27:EB:00:00:01", "--offline", "--json"])
    run(["ask", "scan 192.168.1.1 ports 1-100", "--json"])

    # --- history round trip --------------------------------------------
    run(["history", "--json", "-l", "5"])
    history_json = run(["history", "--json"])
    try:
        entries = json.loads(history_json).get("entries", [])
    except ValueError:
        FAILED.append("history --json did not produce valid JSON")
        entries = []
    else:
        PASSED.append(f"history entries: {len(entries)}")
        if entries:
            run(["history", "--show", str(entries[0]["id"]), "--json"])

    # --- doctor / firewall / plugins -----------------------------------
    run(["doctor", "--json"], expect=0)
    run(["plugins", "--json"])
    run(["firewall", "--json"])
    run(["block", "10.0.0.1", "--dry-run", "--json"])

    # --- cleanup --------------------------------------------------------
    for name in os.listdir(directory):
        if name.startswith("smoke_report"):
            os.remove(os.path.join(directory, name))

    # NetScan records scans in the history db; drop the ones this run made.
    with contextlib.suppress(Exception):
        from modules.history import init_db

        init_db()

    print(f"passed: {len(PASSED)}")
    for name in PASSED:
        print(f"  ok   {name}")
    if FAILED:
        print(f"\nfailed: {len(FAILED)}")
        for name in FAILED:
            print(f"  FAIL {name}")
        return 1
    print("\nall smoke checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
