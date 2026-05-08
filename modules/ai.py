from rich.console import Console

console = Console()


def ai_command_parser(cmd):

    cmd = cmd.lower()

    if "scan" in cmd:

        return "port_scan"

    elif "dns" in cmd:

        return "dns_lookup"

    elif "geo" in cmd:

        return "geo_lookup"

    elif "network" in cmd:

        return "local_network_scan"

    elif "whois" in cmd:

        return "whois_lookup"

    return None


def ai_assistant():

    cmd = input("Ask AI: ")

    result = ai_command_parser(cmd)

    if result:

        console.print(
            f"[green]AI Suggestion:[/green] {result}"
        )

    else:

        console.print(
            "[red]Unknown Command[/red]"
        )