from .console import console

def menu():

    console.print("""
[bold cyan]╔══════════════════════════════════════╗
║            NETSCAN MENU             ║
╚══════════════════════════════════════╝[/bold cyan]

[bold yellow]NETWORK SCANNING[/bold yellow]
[1]  Smart Auto Port Scan
[2]  Fast Port Scan
[3]  Full Port Scan
[15] Ping Test
[16] Traceroute

[bold green]NETWORK INFORMATION[/bold green]
[4]  DNS Lookup
[5]  GeoIP Lookup
[6]  HTTP Header Grabber
[7]  Subdomain Scanner
[9]  WHOIS Lookup
[19] Vendor Detection
[26] Technology Detection

[bold magenta]LOCAL NETWORK[/bold magenta]
[8]  Local Network Scan
[13] Block IP
[14] Unblock IP

[bold blue]SYSTEM & TOOLS[/bold blue]
[10] System Monitor
[11] AI Assistant
[12] Load Plugins
[22] Internet Speed Test
[29] Scan History

[bold red][0] Exit[/bold red]
""")

    console.print(
        "[dim]NETSCAN v4.0 PRO | Advanced Networking Toolkit[/dim]\n"
    )