"""
Runtime environment detection.

The toolkit is written for Termux first, so this module answers the questions
that actually change behaviour there: am I on Termux, am I root, is termux-api
installed, which external tools can I rely on?
"""

from __future__ import annotations

import os
import platform
import shutil
import sys

TERMUX_HOME = "/data/data/com.termux/files/home"
TERMUX_PREFIX = "/data/data/com.termux/files/usr"

# External binaries worth knowing about, with the reason they matter.
OPTIONAL_TOOLS = {
    "ping": "host discovery and latency tests",
    "traceroute": "hop-by-hop path tracing",
    "nmap": "deep service/OS fingerprinting",
    "whois": "offline WHOIS fallback",
    "curl": "HTTP fallbacks and TLS probing",
    "openssl": "certificate inspection",
    "termux-wifi-connectioninfo": "Wi-Fi SSID / IP details",
    "termux-battery-status": "device power telemetry",
    "ip": "interface and neighbour tables",
    "getprop": "Android build properties (root helper)",
}


def prefix() -> str:
    """The Termux ``$PREFIX`` (or the active virtualenv prefix elsewhere)."""
    return os.environ.get("PREFIX") or sys.prefix or TERMUX_PREFIX


def is_termux() -> bool:
    if os.environ.get("TERMUX_VERSION"):
        return True
    if "com.termux" in prefix():
        return True
    return os.path.isdir("/data/data/com.termux/files/usr")


def is_android() -> bool:
    return "android" in platform.platform().lower() or is_termux()


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except (AttributeError, OSError):
        return False


def have(command: str) -> bool:
    """True when ``command`` is runnable on PATH."""
    return shutil.which(command) is not None


def termux_api_ready() -> bool:
    """termux-api works only if both the binary and the app are present."""
    return have("termux-wifi-connectioninfo") or have("termux-battery-status")


def android_version() -> str | None:
    """Best-effort Android release, read from the SDK prop when readable."""
    prop = os.path.join(TERMUX_PREFIX, "..", "..", "..", "system", "build.prop")
    for path in ("/system/build.prop", os.path.normpath(prop)):
        try:
            with open(path, "r", errors="ignore") as handle:
                for line in handle:
                    if line.startswith("ro.build.version.release="):
                        return line.split("=", 1)[1].strip()
        except OSError:
            continue
    return None


def storage_dir() -> str | None:
    """Shared storage, if the user granted it via ``termux-setup-storage``."""
    candidate = os.path.join(os.path.expanduser("~"), "storage", "shared")
    return candidate if os.path.isdir(candidate) else None


def capabilities() -> dict:
    """Everything the rest of the toolkit needs to adapt its behaviour."""
    return {
        "platform": platform.system(),
        "python": platform.python_version(),
        "termux": is_termux(),
        "android": is_android(),
        "android_version": android_version(),
        "root": is_root(),
        "prefix": prefix(),
        "termux_api": termux_api_ready(),
        "storage": storage_dir(),
        "tools": {name: have(name) for name in OPTIONAL_TOOLS},
    }


def missing_tools() -> list[tuple[str, str]]:
    return [
        (name, reason)
        for name, reason in OPTIONAL_TOOLS.items()
        if not have(name)
    ]


def summary_line() -> str:
    caps = capabilities()
    where = "Termux (Android)" if caps["termux"] else caps["platform"]
    mode = "root" if caps["root"] else "standard user"
    return f"{where} | Python {caps['python']} | {mode}"
