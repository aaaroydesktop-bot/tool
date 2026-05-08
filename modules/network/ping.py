import platform
import subprocess
import re
import socket

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# =========================================
# GET LOCAL IP
# =========================================

def get_local_ip():

    try:

        s = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        s.connect(("8.8.8.8", 80))

        ip = s.getsockname()[0]

        s.close()

        return ip

    except:

        return "127.0.0.1"

# =========================================
# GET ROUTER IP
# =========================================

def get_router_ip(local_ip):

    parts = local_ip.split(".")

    return (
        f"{parts[0]}."
        f"{parts[1]}."
        f"{parts[2]}.1"
    )

# =========================================
# OS DETECTION
# =========================================

def detect_os(ttl):

    try:

        ttl = int(ttl)

        if ttl <= 64:

            return "Linux / Android"

        elif ttl <= 128:

            return "Windows"

        elif ttl <= 255:

            return "Network Device"

    except:
        pass

    return "Unknown"

# =========================================
# RUN PING
# =========================================

def run_ping(target):

    try:

        # =====================================
        # COMMAND
        # =====================================

        if platform.system().lower() == "windows":

            command = [
                "ping",
                "-n",
                "4",
                target
            ]

        else:

            command = [
                "ping",
                "-c",
                "4",
                target
            ]

        # =====================================
        # RUN
        # =====================================

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        output = result.stdout

        # =====================================
        # DEFAULTS
        # =====================================

        status = "OFFLINE"

        latency = "N/A"

        ttl = "N/A"

        loss = "0%"

        os_guess = "Unknown"

        # =====================================
        # ONLINE CHECK
        # =====================================

        if "ttl" in output.lower():

            status = "ONLINE"

        # =====================================
        # TTL PARSE
        # =====================================

        ttl_match = re.findall(
            r"ttl[=|:]?\s*(\d+)",
            output,
            re.IGNORECASE
        )

        if ttl_match:

            ttl = ttl_match[0]

            os_guess = detect_os(ttl)

        # =====================================
        # LATENCY PARSE
        # =====================================

        time_match = re.findall(
            r"time[=<]?\s*(\d+)ms",
            output,
            re.IGNORECASE
        )

        if time_match:

            values = list(
                map(int, time_match)
            )

            avg = sum(values) / len(values)

            latency = (
                f"{round(avg,2)} ms"
            )

        # =====================================
        # WINDOWS PACKET LOSS
        # =====================================

        loss_match = re.search(
            r"(\d+)%\s*loss",
            output,
            re.IGNORECASE
        )

        if loss_match:

            loss = (
                loss_match.group(1)
                + "%"
            )

        # =====================================
        # HOSTNAME
        # =====================================

        try:

            hostname = socket.gethostbyaddr(
                target
            )[0]

        except:

            hostname = "Unknown"

        # =====================================
        # RETURN DATA
        # =====================================

        return {
            "target": target,
            "hostname": hostname,
            "status": status,
            "latency": latency,
            "ttl": ttl,
            "loss": loss,
            "os": os_guess
        }

    except Exception as e:

        console.print(
            f"[red]{e}[/red]"
        )

        return None

# =========================================
# MAIN AUTO PING TEST
# =========================================

def ping_test():

    console.print(
        "\n[yellow][*][/yellow] "
        "Running Auto Ping Test..."
    )

    # =====================================
    # AUTO TARGETS
    # =====================================

    local_ip = get_local_ip()

    router_ip = get_router_ip(local_ip)

    internet_ip = "8.8.8.8"

    targets = [
        local_ip,
        router_ip,
        internet_ip
    ]

    # =====================================
    # TABLE
    # =====================================

    table = Table(
        title="Auto Ping Results"
    )

    table.add_column(
        "TARGET",
        style="cyan"
    )

    table.add_column(
        "HOSTNAME",
        style="green"
    )

    table.add_column(
        "STATUS",
        style="yellow"
    )

    table.add_column(
        "LATENCY",
        style="magenta"
    )

    table.add_column(
        "TTL",
        style="blue"
    )

    table.add_column(
        "LOSS",
        style="red"
    )

    table.add_column(
        "OS",
        style="white"
    )

    # =====================================
    # RUN TESTS
    # =====================================

    for target in targets:

        result = run_ping(target)

        if result:

            table.add_row(
                result["target"],
                result["hostname"],
                result["status"],
                result["latency"],
                result["ttl"],
                result["loss"],
                result["os"]
            )

    # =====================================
    # OUTPUT
    # =====================================

    console.print(table)

    console.print(
        Panel.fit(
f"""
[bold green]LOCAL IP[/bold green]
{local_ip}

[bold cyan]ROUTER IP[/bold cyan]
{router_ip}

[bold yellow]INTERNET TEST[/bold yellow]
{internet_ip}
""",
            border_style="cyan"
        )
    )