"""
Example NetScan plugin - reports basic connectivity facts.

Drop any ``*.py`` file defining ``run()`` into this directory and it shows up in
``netscan plugins``. Keep plugins dependency-light: they run in-process.
"""

from core.console import ok
from modules.network import get_local_ip, get_router_ip


def register():
    """Optional metadata shown by ``netscan plugins``."""
    return {
        "name": "sample",
        "description": "prints local IP and gateway",
        "version": "1.0",
    }


def run() -> dict:
    local = get_local_ip()
    gateway = get_router_ip(local)
    ok(f"local IP: {local}   gateway: {gateway}")
    return {"local_ip": local, "gateway": gateway}
