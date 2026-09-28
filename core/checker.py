"""
Dependency and environment checks.

Only ``rich`` is truly required - everything else degrades gracefully, so the
tool reports what is missing with an install hint instead of refusing to start.
"""

from __future__ import annotations

import importlib
import os
import platform
import sqlite3
import sys

from . import EDITION, __version__
from . import report as reportlib
from .console import err, warn

#: Without these the toolkit cannot run at all.
REQUIRED = {"rich": "colour terminal UI"}

#: Needed by the HTTP-based modules (headers, geo, tech, whois, speedtest).
RECOMMENDED = {
    "requests": "HTTP modules (headers, geo, tech, whois, speedtest)",
    "urllib3": "TLS handling for requests",
}

#: Nice to have; each one unlocks a specific extra.
OPTIONAL = {
    "whois": "WHOIS fallback when RDAP has no answer",
    "psutil": "more accurate CPU/RAM metrics on non-Linux hosts",
}

MIN_PYTHON = (3, 9)

#: Module name -> PyPI package name, for the rare cases where they differ.
PIP_NAMES = {"whois": "python-whois"}


def pip_name(module: str) -> str:
    """PyPI package that provides ``module``."""
    return PIP_NAMES.get(module, module)


def _hint(module: str) -> str:
    return f"pip install {pip_name(module)}"


_PKG_HINT = {name: _hint(name) for name in (*REQUIRED, *RECOMMENDED, *OPTIONAL)}


def missing(modules: dict[str, str]) -> list[str]:
    absent = []
    for name in modules:
        try:
            importlib.import_module(name)
        except ImportError:
            absent.append(name)
    return absent


def check_modules(strict: bool = False) -> list[str]:
    """
    Verify imports.  Exits only when a *required* module is missing.

    Returns the list of missing optional modules so callers can surface hints.
    """
    absent_required = missing(REQUIRED)
    if absent_required:
        for name in absent_required:
            err(f"missing required module '{name}' - {REQUIRED[name]}")
        err(f"install it with: {_PKG_HINT.get(absent_required[0], 'pip install ' + absent_required[0])}")
        sys.exit(1)

    absent_recommended = missing(RECOMMENDED)
    absent_optional = missing(OPTIONAL)

    if absent_recommended and not strict:
        warn(
            "missing recommended modules: "
            + ", ".join(absent_recommended)
            + " - some commands will be unavailable"
        )
        warn("install them with: pip install -r requirements.txt")

    return absent_recommended + absent_optional


def doctor(strict: bool = False) -> dict:
    """Full environment diagnosis as a report dict."""
    from . import environment

    report = reportlib.new_report("doctor", platform.node() or "device")
    healthy = True

    def check(name: str, status: str, detail: str) -> None:
        nonlocal healthy
        reportlib.add_finding(report, check=name, status=status, detail=detail)
        if status == "fail":
            healthy = False

    # --- Python ---------------------------------------------------------
    if sys.version_info >= MIN_PYTHON:
        check("python version", "ok", f"{platform.python_version()}")
    else:
        check("python version", "fail",
              f"{platform.python_version()} - need "
              f"{'.'.join(str(p) for p in MIN_PYTHON)}+; run: pkg upgrade python")

    # --- modules --------------------------------------------------------
    for name, why in REQUIRED.items():
        try:
            importlib.import_module(name)
            check(f"module: {name}", "ok", why)
        except ImportError:
            check(f"module: {name}", "fail", f"{why} - {_PKG_HINT.get(name)}")

    for name, why in RECOMMENDED.items():
        try:
            importlib.import_module(name)
            check(f"module: {name}", "ok", why)
        except ImportError:
            check(f"module: {name}", "warn", f"{why} - {_PKG_HINT.get(name)}")

    missing_optional = []
    for name, why in OPTIONAL.items():
        try:
            importlib.import_module(name)
            check(f"module: {name}", "ok", why)
        except ImportError:
            missing_optional.append(name)
            check(f"module: {name}", "warn", f"{why} - optional")

    # --- environment ----------------------------------------------------
    termux = environment.is_termux()
    check("termux", "ok" if termux else "warn",
          "Termux detected" if termux else
          f"not Termux ({platform.system()}); Android-only features stay disabled")

    check("root", "ok" if environment.is_root() else "warn",
          "running as root" if environment.is_root() else
          "standard user - firewall rules need root")

    api = environment.termux_api_ready()
    check("termux-api", "ok" if api else "warn",
          "termux-api available" if api else
          "not installed - Wi-Fi/battery details unavailable (pkg install termux-api)")

    check("storage access", "ok" if environment.storage_dir() else "warn",
          environment.storage_dir() or "run termux-setup-storage to export reports easily")

    tools = environment.capabilities()["tools"]
    for name in ("ping", "traceroute", "nmap", "whois"):
        check(f"tool: {name}", "ok" if tools.get(name) else "warn",
              "found" if tools.get(name) else f"missing - pkg install {name}")

    # --- writable paths -------------------------------------------------
    for label, directory in (("database", "database"), ("reports", "reports")):
        try:
            os.makedirs(directory, exist_ok=True)
            probe = os.path.join(directory, ".netscan-write-test")
            with open(probe, "w", encoding="utf-8") as handle:
                handle.write("ok")
            os.remove(probe)
            check(f"{label} dir writable", "ok", os.path.abspath(directory))
        except OSError as exc:
            check(f"{label} dir writable", "fail", f"{directory}: {exc}")

    # --- history --------------------------------------------------------
    history_entries = 0
    try:
        from modules.history import stats as history_stats

        data = history_stats()
        history_entries = data.get("total", 0)
        check("history database", "ok", f"{history_entries} entries")
    except (sqlite3.Error, ImportError, OSError) as exc:
        check("history database", "warn", f"unavailable: {exc}")

    reportlib.finish(
        report,
        healthy=healthy,
        version=__version__,
        edition=EDITION,
        history_entries=history_entries,
        missing_optional=missing_optional,
    )
    return report
