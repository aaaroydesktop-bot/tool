import requests

from rich.console import Console
from rich.table import Table

console = Console()

def http_headers():

    url = input("URL: ")

    if not url.startswith("http"):
        url = "http://" + url

    try:

        response = requests.get(
            url,
            timeout=5
        )

        table = Table(title="HTTP Headers")

        table.add_column("HEADER")
        table.add_column("VALUE")

        for k, v in response.headers.items():

            table.add_row(k, str(v))

        console.print(table)

    except Exception as e:

        console.print(
            f"[red]{e}[/red]"
        )