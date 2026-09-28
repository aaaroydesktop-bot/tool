"""
A minimal stand-in for Rich.

NetScan's only hard dependency is Rich, and every other import is lazy.  When
Rich is genuinely unavailable (a bare Termux install, minimal CI) this module
lets the import graph, the CLI wiring and the scanning engine still be
exercised - it renders nothing, but it never raises.
"""

from __future__ import annotations

import sys
import types


class _DummyMeta(type):
    """Lets class-level access work too (e.g. ``Panel.fit(...)``)."""

    def __getattr__(cls, name):
        return _Dummy


class _Dummy(metaclass=_DummyMeta):
    """Permissive stand-in for any Rich object."""

    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, *args, **kwargs):
        return _Dummy()

    def __getattr__(self, name):
        return _Dummy()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def __iter__(self):
        return iter(())

    # methods whose return value the code actually uses
    def add_task(self, *args, **kwargs):
        return 0

    def ask(self, *args, **kwargs):
        return ""

    def print(self, *args, **kwargs):
        """Mirror Console.print for ``--help``-style smoke checks."""
        text = " ".join(str(arg) for arg in args)
        if text:
            sys.stdout.write(text + "\n")


_RICH_SUBMODULES = (
    "console", "table", "panel", "progress", "prompt", "live",
    "text", "traceback", "box", "rule", "markdown",
)


def install() -> bool:
    """Install the stub if Rich is missing.  Returns True when it was used."""
    try:
        import rich  # noqa: F401

        return False
    except ImportError:
        pass

    rich = types.ModuleType("rich")
    rich.__path__ = []  # so 'from rich.x import y' resolves via sys.modules

    def _make(name):
        module = types.ModuleType(name)
        module.__getattr__ = lambda attribute: _Dummy
        sys.modules[name] = module
        return module

    for submodule in _RICH_SUBMODULES:
        _make(f"rich.{submodule}")

    rich.__getattr__ = lambda attribute: sys.modules.get(f"rich.{attribute}", _Dummy)
    sys.modules["rich"] = rich
    return True
