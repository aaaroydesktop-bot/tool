import whois

from rich.console import Console

console = Console()

def whois_lookup():
    domain = input("Domain: ")

    try:
        data = whois.whois(domain)

        console.print(data)

    except Exception as e:
        console.print(e)