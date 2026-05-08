import requests

from rich.console import Console
from rich.table import Table

console = Console()


def vendor_lookup():

    mac = input("MAC Address: ")

    try:

        url = f"https://api.macvendors.com/{mac}"

        vendor = requests.get(
            url,
            timeout=5
        ).text

        table = Table(title="Vendor Detection")

        table.add_column("MAC")
        table.add_column("VENDOR")

        table.add_row(mac, vendor)

        console.print(table)

    except Exception as e:

        console.print(f"[red]{e}[/red]")