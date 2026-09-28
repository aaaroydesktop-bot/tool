"""Startup banner."""

from __future__ import annotations

from rich.panel import Panel

from . import TOOL_NAME, __version__
from .console import console
from .environment import is_root, is_termux, summary_line
from .utils import clear

_LOGO = """
[bold cyan]
███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
[/bold cyan]
"""


def banner(show_logo: bool = True) -> None:
    """Draw the banner.  ``show_logo=False`` gives a compact one-liner."""
    if show_logo:
        clear()

    target = "Termux / Android" if is_termux() else "Desktop"

    body = _LOGO + (
        f"\n[bold green]{TOOL_NAME} {__version__}[/bold green] "
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

    if is_root():
        console.print("[bold green][ROOT MODE ENABLED][/bold green]")
    else:
        console.print("[bold yellow][STANDARD USER MODE][/bold yellow]")
