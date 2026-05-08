import os

from rich.panel import Panel

from .console import console
from .utils import clear, is_admin

def banner():

    clear()

    if os.name == "nt":

        os.system("title NETSCAN")

    console.print(
        Panel.fit(
"""
[bold cyan]
███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
[/bold cyan]

[bold green]Advanced Termux Networking Toolkit[/bold green]

[white]Developer : Anupom Roy[/white]
[white]Version   : 4.0 Pro[/white]
""",
            border_style="cyan",
            padding=(1, 2)
        )
    )

    if is_admin():

        console.print(
            "[bold green][ROOT MODE ENABLED][/bold green]"
        )

    else:

        console.print(
            "[bold yellow][STANDARD USER MODE][/bold yellow]"
        )