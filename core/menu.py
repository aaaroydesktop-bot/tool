"""
Menu rendering.

The menu is built from the *same* registry that main.py dispatches on, so a
displayed option can never be missing an implementation (or vice versa).
"""

from __future__ import annotations

from rich.table import Table

from .console import console


def render(sections, columns: int = 2) -> None:
    """
    Print grouped menu items.

    ``sections`` is ``[(title, [(number, label), ...]), ...]``.
    """
    for title, items in sections:
        if not items:
            continue
        table = Table(
            title=f"[bold cyan]{title}[/bold cyan]",
            show_header=False,
            box=None,
            pad_edge=False,
            title_justify="left",
        )
        for _ in range(columns):
            table.add_column(style="cyan", justify="right", no_wrap=True)
            table.add_column(style="white", overflow="fold", no_wrap=False)

        rows = [items[index:index + columns] for index in range(0, len(items), columns)]
        for row in rows:
            cells: list[str] = []
            for number, label in row:
                cells += [f"[bold]{number}[/bold]", label]
            while len(cells) < columns * 2:
                cells += ["", ""]
            table.add_row(*cells)

        console.print(table)


def menu(sections) -> None:
    """Compatibility shim: `menu(sections)` renders like :func:`render`."""
    render(sections)


def blank_line() -> None:
    console.print()
