import time
import psutil
import platform
import socket
import threading

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live

console = Console()

# =========================================
# STOP FLAG
# =========================================

stop_monitor = False

# =========================================
# KEY LISTENER
# =========================================

def wait_for_exit():

    global stop_monitor

    while True:

        cmd = input()

        if cmd.lower() == "q":

            stop_monitor = True

            break

# =========================================
# SYSTEM MONITOR
# =========================================

def system_monitor():

    global stop_monitor

    stop_monitor = False

    console.print(
        "\n[yellow][*][/yellow] "
        "Starting Live System Monitor..."
    )

    console.print(
        "[red]Press 'q' + Enter To Go Back[/red]\n"
    )

    # =====================================
    # START INPUT THREAD
    # =====================================

    thread = threading.Thread(
        target=wait_for_exit,
        daemon=True
    )

    thread.start()

    try:

        with Live(
            refresh_per_second=1,
            screen=True
        ) as live:

            while not stop_monitor:

                # =================================
                # CPU
                # =================================

                cpu = psutil.cpu_percent()

                # =================================
                # RAM
                # =================================

                ram = psutil.virtual_memory()

                ram_percent = ram.percent

                ram_used = round(
                    ram.used / (1024**3),
                    2
                )

                ram_total = round(
                    ram.total / (1024**3),
                    2
                )

                # =================================
                # DISK
                # =================================

                disk = psutil.disk_usage("/")

                disk_percent = disk.percent

                # =================================
                # NETWORK
                # =================================

                net = psutil.net_io_counters()

                sent = round(
                    net.bytes_sent / (1024**2),
                    2
                )

                recv = round(
                    net.bytes_recv / (1024**2),
                    2
                )

                # =================================
                # SYSTEM INFO
                # =================================

                hostname = socket.gethostname()

                system = platform.system()

                release = platform.release()

                # =================================
                # TABLE
                # =================================

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
                    f"{ram_percent}%"
                )

                table.add_row(
                    "RAM Used",
                    f"{ram_used} GB / "
                    f"{ram_total} GB"
                )

                table.add_row(
                    "Disk Usage",
                    f"{disk_percent}%"
                )

                table.add_row(
                    "Upload",
                    f"{sent} MB"
                )

                table.add_row(
                    "Download",
                    f"{recv} MB"
                )

                table.add_row(
                    "Hostname",
                    hostname
                )

                table.add_row(
                    "System",
                    f"{system} {release}"
                )

                # =================================
                # PANEL
                # =================================

                panel = Panel.fit(
                    table,
                    border_style="cyan"
                )

                live.update(panel)

                time.sleep(1)

    except KeyboardInterrupt:

        pass

    console.print(
        "\n[green][+][/green] "
        "Returning To Main Menu..."
    )