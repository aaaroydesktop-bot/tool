import socket
import subprocess
import concurrent.futures
import platform

from rich.console import Console
from rich.table import Table
from rich.progress import Progress

console = Console()

def ping_ip(ip):

    try:

        if platform.system().lower() == "windows":

            command = [
                "ping",
                "-n",
                "1",
                "-w",
                "300",
                ip
            ]

        else:

            command = [
                "ping",
                "-c",
                "1",
                "-W",
                "1",
                ip
            ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        output = result.stdout.lower()

        if "ttl=" in output:
            return True

        if "1 received" in output:
            return True

    except:
        pass

    return False

def get_hostname(ip):

    try:
        return socket.gethostbyaddr(ip)[0]

    except:
        return "Unknown"

def get_mac(ip):

    try:

        if platform.system().lower() == "windows":

            arp = subprocess.check_output(
                "arp -a",
                shell=True
            ).decode()

            for line in arp.splitlines():

                if ip in line:

                    parts = line.split()

                    if len(parts) >= 2:

                        return parts[1]

        else:

            with open("/proc/net/arp") as f:

                for line in f.readlines():

                    if ip in line:

                        return line.split()[3]

    except:
        pass

    return "Unknown"

def local_network_scan():

    console.print(
        "\n[yellow][*][/yellow] Scanning Local Network..."
    )

    try:

        s = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        s.connect(("8.8.8.8", 80))

        local_ip = s.getsockname()[0]

        s.close()

    except:

        console.print(
            "[red][-] Could Not Detect Local IP[/red]"
        )

        return

    console.print(
        f"[green]Your IP:[/green] {local_ip}"
    )

    ip_parts = local_ip.split(".")

    base_ip = (
        f"{ip_parts[0]}."
        f"{ip_parts[1]}."
        f"{ip_parts[2]}."
    )

    table = Table(title="Connected Devices")

    table.add_column("IP ADDRESS", style="cyan")
    table.add_column("HOSTNAME", style="green")
    table.add_column("MAC ADDRESS", style="yellow")

    active = []

    with Progress() as progress:

        task = progress.add_task(
            "[green]Scanning...",
            total=254
        )

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=100
        ) as executor:

            futures = {}

            for i in range(1, 255):

                ip = f"{base_ip}{i}"

                future = executor.submit(
                    ping_ip,
                    ip
                )

                futures[future] = ip

            for future in concurrent.futures.as_completed(
                futures
            ):

                ip = futures[future]

                try:

                    if future.result():

                        hostname = get_hostname(ip)

                        mac = get_mac(ip)

                        active.append(ip)

                        table.add_row(
                            ip,
                            hostname,
                            mac
                        )

                except:
                    pass

                progress.update(task, advance=1)

    console.print(table)

    console.print(
        f"\n[green][+][/green] Devices Found: "
        f"{len(active)}"
    )