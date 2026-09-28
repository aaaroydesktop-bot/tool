"""
NetScan feature modules.

Submodules are imported lazily (PEP 562).  On Termux every avoided import is
measurable startup time, and commands like ``netscan ping`` should never pay for
loading the HTTP stack.
"""

from __future__ import annotations

import importlib

_SUBMODULES = (
    "network",
    "osint",
    "monitoring",
    "history",
    "firewall",
    "plugins",
    "reporting",
    "ai",
)

__all__ = list(_SUBMODULES)


def __getattr__(name: str):
    if name in _SUBMODULES:
        module = importlib.import_module(f"{__name__}.{name}")
        globals()[name] = module
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(set(globals()) | set(_SUBMODULES))
