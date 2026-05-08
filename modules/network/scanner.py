import socket
import concurrent.futures
import time

from rich.console import Console
from rich.table import Table
from rich.progress import Progress

from .services import COMMON_SERVICES, SMART_PORTS

console = Console()

def scan_port(target, port):

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(0.2)

        result = sock.connect_ex((target, port))

        if result == 0:

            service = COMMON_SERVICES.get(
                port,
                "Unknown"
            )

            banner = "Unknown"

            try:

                banner = sock.recv(
                    1024
                ).decode(
                    errors="ignore"
                ).strip()

                banner = banner[:50]

            except:
                pass

            sock.close()

            return {
                "port": port,
                "service": service,
                "banner": banner
            }

        sock.close()

    except:
        pass

    return None

def port_scan(target, start, end):

    console.print(
        f"\n[yellow][*][/yellow] Scanning {target}..."
    )

    try:

        target_ip = socket.gethostbyname(target)

    except:

        console.print(
            "[red][-] Invalid Target[/red]"
        )

        return

    table = Table(title="Open Ports")

    table.add_column("PORT", style="cyan")
    table.add_column("SERVICE", style="green")
    table.add_column("BANNER", style="yellow")

    ports = range(start, end + 1)

    open_count = 0

    start_time = time.time()

    with Progress() as progress:

        task = progress.add_task(
            "[green]Scanning...",
            total=len(ports)
        )

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=200
        ) as executor:

            futures = {
                executor.submit(
                    scan_port,
                    target_ip,
                    port
                ): port for port in ports
            }

            for future in concurrent.futures.as_completed(
                futures
            ):

                result = future.result()

                progress.update(task, advance=1)

                if result:

                    open_count += 1

                    table.add_row(
                        str(result["port"]),
                        result["service"],
                        result["banner"]
                    )

    end_time = time.time()

    console.print(table)

    console.print(
        f"\n[green][+][/green] Open Ports: {open_count}"
    )

    console.print(
        f"[cyan][+][/cyan] Time Taken: "
        f"{round(end_time - start_time, 2)} sec"
    )

def auto_port_scan():

    target = input("Target IP/Domain: ")

    console.print(
        "\n[yellow][*][/yellow] Running Smart Auto Scan..."
    )

    try:

        target_ip = socket.gethostbyname(target)

    except:

        console.print(
            "[red][-] Invalid Target[/red]"
        )

        return

    table = Table(title="Smart Scan Results")

    table.add_column("PORT", style="cyan")
    table.add_column("SERVICE", style="green")
    table.add_column("STATUS", style="yellow")

    open_count = 0

    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=200
    ) as executor:

        futures = {
            executor.submit(
                scan_port,
                target_ip,
                port
            ): port for port in SMART_PORTS
        }

        for future in concurrent.futures.as_completed(
            futures
        ):

            result = future.result()

            if result:

                open_count += 1

                table.add_row(
                    str(result["port"]),
                    result["service"],
                    "OPEN"
                )

    end_time = time.time()

    console.print(table)

    console.print(
        f"\n[green][+][/green] Open Ports: {open_count}"
    )

    console.print(
        f"[cyan][+][/cyan] Scan Time: "
        f"{round(end_time - start_time, 2)} sec"
    )