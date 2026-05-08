import os
import time
import platform

from rich.console import Console
from rich.table import Table
from rich.live import Live

console = Console()

# =========================================
# RAM USAGE
# =========================================

def get_ram():

    try:

        # TERMUX / LINUX

        if platform.system() != "Windows":

            meminfo = {}

            with open("/proc/meminfo") as f:

                for line in f:

                    key = line.split(":")[0]

                    value = line.split(":")[1]

                    meminfo[key] = int(
                        value.strip().split()[0]
                    )

            total = (
                meminfo["MemTotal"] / 1024
            )

            free = (
                meminfo["MemAvailable"] / 1024
            )

            used = total - free

            percent = (
                used / total
            ) * 100

            return round(percent, 2)

        # WINDOWS

        else:

            import psutil

            return psutil.virtual_memory().percent

    except:

        return 0

# =========================================
# CPU USAGE
# =========================================

def get_cpu():

    try:

        # TERMUX / LINUX

        if platform.system() != "Windows":

            load = os.getloadavg()[0]

            return round(
                load * 100 / os.cpu_count(),
                2
            )

        # WINDOWS

        else:

            import psutil

            return psutil.cpu_percent()

    except:

        return 0

# =========================================
# SYSTEM MONITOR
# =========================================

def system_monitor():

    console.print(
        "\n[yellow][*][/yellow] "
        "Starting System Monitor...\n"
    )

    try:

        with Live(
            refresh_per_second=1,
            screen=True
        ) as live:

            while True:

                cpu = get_cpu()

                ram = get_ram()

                table = Table(
                    title="Live System Monitor"
                )

                table.add_column(
                    "METRIC",
                    style="cyan"
                )

                table.add_column(
                    "VALUE",
                    style="green"
                )

                table.add_row(
                    "CPU Usage",
                    f"{cpu}%"
                )

                table.add_row(
                    "RAM Usage",
                    f"{ram}%"
                )

                table.add_row(
                    "Platform",
                    platform.system()
                )

                table.add_row(
                    "CPU Cores",
                    str(os.cpu_count())
                )

                live.update(table)

                time.sleep(1)

    except KeyboardInterrupt:

        console.print(
            "\n[red]Monitor Stopped[/red]"
        )