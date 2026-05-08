import requests

from rich.console import Console
from rich.table import Table

console = Console()

def geo_lookup():

    ip = input("IP Address: ")

    try:

        data = requests.get(
            f"http://ip-api.com/json/{ip}"
        ).json()

        table = Table(title="GeoIP Info")

        table.add_column("KEY")
        table.add_column("VALUE")

        keys = [
            "country",
            "regionName",
            "city",
            "isp",
            "org",
            "lat",
            "lon"
        ]

        for key in keys:

            table.add_row(
                key,
                str(data.get(key))
            )

        console.print(table)

    except Exception as e:

        console.print(
            f"[red]{e}[/red]"
        )