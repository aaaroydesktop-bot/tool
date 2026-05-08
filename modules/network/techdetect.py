import requests

from rich.console import Console
from rich.table import Table

console = Console()


def detect_technology():

    url = input("Website URL: ")

    if not url.startswith("http"):

        url = "http://" + url

    try:

        response = requests.get(url)

        headers = response.headers

        tech = []

        server = headers.get("Server")

        powered = headers.get("X-Powered-By")

        if server:
            tech.append(server)

        if powered:
            tech.append(powered)

        html = response.text.lower()

        if "wordpress" in html:
            tech.append("WordPress")

        if "cloudflare" in html:
            tech.append("Cloudflare")

        table = Table(title="Technology Detection")

        table.add_column("TECHNOLOGY")

        for t in tech:
            table.add_row(t)

        console.print(table)

    except Exception as e:

        console.print(f"[red]{e}[/red]")