import socket

from rich.console import Console
from rich.table import Table

console = Console()

def subdomain_scan():

    domain = input("Domain: ")

    subdomains = [
        "www",
        "mail",
        "api",
        "dev",
        "admin",
        "test",
        "beta",
        "cdn",
        "ftp",
        "blog"
    ]

    table = Table(title="Subdomains")

    table.add_column("HOST")
    table.add_column("IP")

    found = False

    for sub in subdomains:

        host = f"{sub}.{domain}"

        try:

            ip = socket.gethostbyname(host)

            table.add_row(host, ip)

            found = True

        except:
            pass

    if found:

        console.print(table)

    else:

        console.print(
            "[red]No Subdomains Found[/red]"
        )