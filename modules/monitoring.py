import psutil

from rich.console import Console

console = Console()

def system_monitor():
    cpu = psutil.cpu_percent()
    ram = psutil.virtual_memory().percent

    console.print(f"[green]CPU:[/green] {cpu}%")
    console.print(f"[cyan]RAM:[/cyan] {ram}%")

    battery = psutil.sensors_battery()

    if battery:
        console.print(f"[yellow]Battery:[/yellow] {battery.percent}%")