import importlib
import sys

from .console import console

# =========================================
# REQUIRED MODULES
# =========================================

REQUIRED_MODULES = [
    "rich",
    "requests",
    "aiohttp",
    "whois",
    "jinja2",
    "scapy",
    "urllib3"
]

# =========================================
# CHECK MODULES
# =========================================

def check_modules():

    missing = []

    for module in REQUIRED_MODULES:

        try:

            importlib.import_module(module)

        except ImportError:

            missing.append(module)

    if missing:

        console.print(
            f"[red]Missing Modules:[/red] "
            f"{', '.join(missing)}"
        )

        console.print(
            "[yellow]Run:[/yellow] "
            "pip install -r requirements.txt"
        )

        sys.exit()