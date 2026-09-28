"""Terminal and OS level helpers.  No third-party imports needed here."""

from __future__ import annotations

import os
import re
import sys

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def clear() -> None:
    """Clear the screen, but do not emit escape junk when not a TTY."""
    if not sys.stdout.isatty():
        return
    os.system("cls" if os.name == "nt" else "clear")


def is_admin() -> bool:
    """Root / Administrator check that never raises on odd platforms."""
    try:
        return os.geteuid() == 0
    except (AttributeError, OSError):
        try:  # Windows
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text or "")


def pause(message: str = "Press Enter To Continue") -> None:
    from rich.prompt import Prompt

    try:
        Prompt.ask(f"\n[cyan]{message}[/cyan]")
    except (EOFError, KeyboardInterrupt):
        raise KeyboardInterrupt


def ask(prompt: str, default: str | None = None) -> str:
    """Prompt for a value; KeyboardInterrupt / EOF bubble up to the caller."""
    from rich.prompt import Prompt

    return Prompt.ask(f"[bold green]{prompt}[/bold green]", default=default)


def is_tty() -> bool:
    return sys.stdout.isatty()
