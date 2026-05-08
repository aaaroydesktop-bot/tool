import os
import platform
import subprocess

from rich.console import Console

console = Console()

# =========================
# BLOCK IP
# =========================

def block_ip():

    ip = input("IP To Block: ")

    try:

        # WINDOWS
        if platform.system().lower() == "windows":

            command = (
                f'netsh advfirewall firewall add rule '
                f'name="Block_{ip}" '
                f'dir=in action=block remoteip={ip}'
            )

            subprocess.run(
                command,
                shell=True
            )

        # LINUX / TERMUX
        else:

            command = [
                "iptables",
                "-A",
                "INPUT",
                "-s",
                ip,
                "-j",
                "DROP"
            ]

            subprocess.run(command)

        console.print(
            f"[green][+][/green] Blocked {ip}"
        )

    except Exception as e:

        console.print(
            f"[red]{e}[/red]"
        )

# =========================
# UNBLOCK IP
# =========================

def unblock_ip():

    ip = input("IP To Unblock: ")

    try:

        # WINDOWS
        if platform.system().lower() == "windows":

            command = (
                f'netsh advfirewall firewall delete rule '
                f'name="Block_{ip}"'
            )

            subprocess.run(
                command,
                shell=True
            )

        # LINUX / TERMUX
        else:

            command = [
                "iptables",
                "-D",
                "INPUT",
                "-s",
                ip,
                "-j",
                "DROP"
            ]

            subprocess.run(command)

        console.print(
            f"[green][+][/green] Unblocked {ip}"
        )

    except Exception as e:

        console.print(
            f"[red]{e}[/red]"
        )