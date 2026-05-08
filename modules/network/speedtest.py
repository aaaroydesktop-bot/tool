import requests
import time
import urllib3

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress

# =========================================
# DISABLE SSL WARNING
# =========================================

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

console = Console()

# =========================================
# INTERNET SPEED TEST
# =========================================

def speed_test():

    console.print(
        "\n[yellow][*][/yellow] Running Advanced Speed Test..."
    )

    # =====================================
    # TEST FILE
    # =====================================

    url = (
        "https://proof.ovh.net/files/10Mb.dat"
    )

    try:

        start = time.time()

        response = requests.get(
            url,
            stream=True,
            verify=False,
            timeout=30
        )

        total_size = int(
            response.headers.get(
                "content-length",
                0
            )
        )

        downloaded = 0

        chunk_size = 1024

        # =====================================
        # DOWNLOAD WITH PROGRESS
        # =====================================

        with Progress() as progress:

            task = progress.add_task(
                "[cyan]Downloading...",
                total=total_size
            )

            for chunk in response.iter_content(
                chunk_size=chunk_size
            ):

                if chunk:

                    downloaded += len(chunk)

                    progress.update(
                        task,
                        advance=len(chunk)
                    )

        end = time.time()

        # =====================================
        # CALCULATIONS
        # =====================================

        total_time = (
            end - start
        )

        size_mb = (
            downloaded / 1024 / 1024
        )

        speed_mb = (
            size_mb / total_time
        )

        speed_mbps = (
            speed_mb * 8
        )

        # =====================================
        # SPEED STATUS
        # =====================================

        if speed_mb < 1:

            status = "Very Slow"

        elif speed_mb < 5:

            status = "Normal"

        elif speed_mb < 20:

            status = "Fast"

        else:

            status = "Very Fast"

        # =====================================
        # ESTIMATED PING
        # =====================================

        ping_estimate = round(
            (1000 / speed_mbps),
            2
        )

        # =====================================
        # TABLE
        # =====================================

        table = Table(
            title="Advanced Internet Speed Test"
        )

        table.add_column(
            "DOWNLOAD",
            style="green"
        )

        table.add_column(
            "Mbps",
            style="cyan"
        )

        table.add_column(
            "TIME",
            style="yellow"
        )

        table.add_column(
            "PING",
            style="magenta"
        )

        table.add_column(
            "STATUS",
            style="red"
        )

        table.add_row(
            f"{round(speed_mb,2)} MB/s",
            f"{round(speed_mbps,2)} Mbps",
            f"{round(total_time,2)} sec",
            f"{ping_estimate} ms",
            status
        )

        console.print(table)

        # =====================================
        # EXTRA INFO PANEL
        # =====================================

        console.print(
            Panel.fit(
f"""
[bold green]DOWNLOADED[/bold green]
{round(size_mb,2)} MB

[bold cyan]AVERAGE SPEED[/bold cyan]
{round(speed_mb,2)} MB/s

[bold yellow]MEGABITS[/bold yellow]
{round(speed_mbps,2)} Mbps

[bold magenta]ESTIMATED PING[/bold magenta]
{ping_estimate} ms

[bold red]NETWORK QUALITY[/bold red]
{status}
""",
                border_style="cyan"
            )
        )

    except requests.exceptions.ConnectionError:

        console.print(
            "[red][-] No Internet Connection[/red]"
        )

    except requests.exceptions.Timeout:

        console.print(
            "[red][-] Connection Timed Out[/red]"
        )

    except Exception as e:

        console.print(
            f"[red]{e}[/red]"
        )