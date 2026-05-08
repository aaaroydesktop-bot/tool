import socket

from rich.console import Console

console = Console()

def dns_lookup():

    target = input("Domain/IP: ")

    try:

        ip = socket.gethostbyname(target)

        console.print(
            f"[green]IP:[/green] {ip}"
        )

        try:

            host = socket.gethostbyaddr(ip)

            console.print(
                f"[cyan]Hostname:[/cyan] {host[0]}"
            )

        except:
            pass

    except Exception as e:

        console.print(
            f"[red]{e}[/red]"
        )