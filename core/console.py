"""
One shared Rich console for the whole toolkit.

Every module does ``from core.console import console``.  The object below is a
live proxy, so ``configure()`` can swap the underlying Rich console (for
``--no-color`` / ``--quiet``) without breaking already-imported references.

``--quiet`` only silences the ``info/ok/warn`` helpers and ``say()``.  Errors
always go to stderr so they survive redirection.
"""

from __future__ import annotations

import os
import sys

from rich.console import Console


class _LiveConsole:
    """Forwards every attribute lookup to the currently configured console."""

    def __getattr__(self, name):
        return getattr(_state["console"], name)

    def __repr__(self):  # pragma: no cover - debugging aid
        return f"<LiveConsole {_state['console']!r}>"


_state = {
    "console": Console(highlight=False),
    "stderr": Console(stderr=True, highlight=False),
    "quiet": False,
}

console = _LiveConsole()


def configure(quiet: bool = False, color: bool | None = None, stderr_only_colors: bool = False):
    """Rebuild the shared consoles.  Safe to call more than once."""
    if color is False:
        os.environ["NO_COLOR"] = "1"
    elif color is True:
        os.environ.pop("NO_COLOR", None)

    _state["console"] = Console(highlight=False)
    _state["stderr"] = Console(stderr=True, highlight=False)
    _state["quiet"] = bool(quiet)
    return console


def is_quiet() -> bool:
    return _state["quiet"]


def say(*objects, **kwargs):
    """Print unless ``--quiet`` is active."""
    if not _state["quiet"]:
        _state["console"].print(*objects, **kwargs)


def info(message) -> None:
    say(f"[cyan][*][/cyan] {message}")


def ok(message) -> None:
    say(f"[green][+][/green] {message}")


def warn(message) -> None:
    say(f"[yellow][!][/yellow] {message}")


def err(message) -> None:
    """Errors go to stderr and are never silenced."""
    _state["stderr"].print(f"[red][x][/red] {message}")


def section(title: str) -> None:
    say(f"\n[bold cyan]{title}[/bold cyan]")


def json_out(payload) -> None:
    """Machine readable output: always plain, always on stdout."""
    import json

    sys.stdout.write(json.dumps(payload, indent=2, default=str) + "\n")
    sys.stdout.flush()
