import platform
import subprocess

from rich.console import Console

console = Console()


def traceroute():

    target = input("Target IP/Domain: ")

    try:

        if platform.system().lower() == "windows":

            command = ["tracert", target]

        else:

            command = ["traceroute", target]

        subprocess.run(command)

    except Exception as e:

        console.print(f"[red]{e}[/red]")