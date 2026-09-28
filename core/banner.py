"""Startup banner.

The block-art logo only renders on a UTF-8 terminal.  Termux is UTF-8, but a
Windows console (cp1252) or a bare ``LANG=C`` shell raises
``UnicodeEncodeError`` mid-print — which used to kill the interactive menu
before it drew anything.  So the logo is chosen per console, with an ASCII
fallback.
"""

from __future__ import annotations

import sys

from rich.panel import Panel

from . import TOOL_NAME, VERSION_LABEL
from .console import console
from .environment import is_root, is_termux, summary_line
from .utils import clear

_LOGO_UNICODE = """
[bold cyan]
███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
[/bold cyan]
"""

#: Plain-ASCII stand-in, used when the console encoding cannot hold the art.
_LOGO_ASCII = """
[bold cyan]
      ============================
           N E T S C A N
               5.0  Pro
      ============================
[/bold cyan]
"""


def _stdout_encoding() -> str:
    """Encoding of the terminal we are writing to (``ascii`` when unknown)."""
    return getattr(sys.stdout, "encoding", None) or "ascii"


def _can_encode(text: str) -> bool:
    """True when the console's encoding can represent ``text``."""
    try:
        text.encode(_stdout_encoding())
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def logo() -> str:
    """The prettiest logo this terminal can actually display."""
    return _LOGO_UNICODE if _can_encode(_LOGO_UNICODE) else _LOGO_ASCII


def banner(show_logo: bool = True) -> None:
    """Draw the banner.  ``show_logo=False`` gives a compact one-liner."""
    if show_logo:
        clear()

    target = "Termux / Android" if is_termux() else "Desktop"

    try:
        body = logo() + (
            f"\n[bold green]{TOOL_NAME} {VERSION_LABEL}[/bold green] "
            f"[dim]| {target} networking toolkit[/dim]\n"
            f"[dim]{summary_line()}[/dim]"
        )
        console.print(
            Panel.fit(
                body,
                border_style="cyan",
                padding=(0, 2),
                title=f"[bold cyan]{TOOL_NAME}[/bold cyan]",
                subtitle="[dim]type 0 to exit[/dim]",
            )
        )
    except UnicodeEncodeError:
        # Last-ditch guard: never let decoration take the menu down.
        console.print(f"[bold cyan]{TOOL_NAME} {VERSION_LABEL}[/bold cyan]")

    if is_root():
        console.print("[bold green][ROOT MODE ENABLED][/bold green]")
    else:
        console.print("[bold yellow][STANDARD USER MODE][/bold yellow]")
