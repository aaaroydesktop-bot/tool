#!/usr/bin/env python

# =========================================
# IMPORTS
# =========================================

import time

from rich.prompt import Prompt
from rich.traceback import install

install()

# =========================================
# CORE IMPORTS
# =========================================

from core.banner import banner
from core.menu import menu
from core.checker import check_modules
from core.console import console

# =========================================
# MODULE IMPORTS
# =========================================

from modules import network
from modules import osint
from modules import monitoring
from modules import ai
from modules import plugins
from modules import firewall

from modules.history import (
    init_db,
    save_history,
    show_history
)

# =========================================
# STARTUP CHECKS
# =========================================

check_modules()

init_db()

# =========================================
# MAIN LOOP
# =========================================

def main():

    while True:

        try:

            # =====================================
            # UI
            # =====================================

            banner()

            menu()

            choice = Prompt.ask(
                "[bold green]Select Option[/bold green]"
            )

            console.print(
                "\n[yellow][*][/yellow] Processing...\n"
            )

            time.sleep(0.3)

            # =====================================
            # SMART AUTO PORT SCAN
            # =====================================

            if choice == "1":

                target = Prompt.ask(
                    "Target IP/Domain"
                )

                save_history(
                    "smart_scan",
                    target
                )

                network.auto_port_scan()

            # =====================================
            # FAST PORT SCAN
            # =====================================

            elif choice == "2":

                target = Prompt.ask(
                    "Target IP/Domain"
                )

                save_history(
                    "fast_scan",
                    target
                )

                network.port_scan(
                    target,
                    1,
                    1024
                )

            # =====================================
            # FULL PORT SCAN
            # =====================================

            elif choice == "3":

                target = Prompt.ask(
                    "Target IP/Domain"
                )

                save_history(
                    "full_scan",
                    target
                )

                network.port_scan(
                    target,
                    1,
                    65535
                )

            # =====================================
            # DNS LOOKUP
            # =====================================

            elif choice == "4":

                save_history(
                    "dns_lookup",
                    "manual"
                )

                network.dns_lookup()

            # =====================================
            # GEOIP LOOKUP
            # =====================================

            elif choice == "5":

                save_history(
                    "geoip_lookup",
                    "manual"
                )

                network.geo_lookup()

            # =====================================
            # HTTP HEADER GRABBER
            # =====================================

            elif choice == "6":

                save_history(
                    "http_headers",
                    "manual"
                )

                network.http_headers()

            # =====================================
            # SUBDOMAIN SCANNER
            # =====================================

            elif choice == "7":

                save_history(
                    "subdomain_scan",
                    "manual"
                )

                network.subdomain_scan()

            # =====================================
            # LOCAL NETWORK SCAN
            # =====================================

            elif choice == "8":

                save_history(
                    "local_network_scan",
                    "local"
                )

                network.local_network_scan()

            # =====================================
            # WHOIS LOOKUP
            # =====================================

            elif choice == "9":

                save_history(
                    "whois_lookup",
                    "manual"
                )

                osint.whois_lookup()

            # =====================================
            # SYSTEM MONITOR
            # =====================================

            elif choice == "10":

                save_history(
                    "system_monitor",
                    "local_system"
                )

                monitoring.system_monitor()

            # =====================================
            # AI ASSISTANT
            # =====================================

            elif choice == "11":

                ai.ai_assistant()

            # =====================================
            # LOAD PLUGINS
            # =====================================

            elif choice == "12":

                plugins.load_plugins()

            # =====================================
            # BLOCK IP
            # =====================================

            elif choice == "13":

                firewall.block_ip()

            # =====================================
            # UNBLOCK IP
            # =====================================

            elif choice == "14":

                firewall.unblock_ip()

            # =====================================
            # PING TEST
            # =====================================

            elif choice == "15":

                save_history(
                    "ping_test",
                    "manual"
                )

                network.ping_test()

            # =====================================
            # TRACEROUTE
            # =====================================

            elif choice == "16":

                save_history(
                    "traceroute",
                    "manual"
                )

                network.traceroute()

            # =====================================
            # VENDOR DETECTION
            # =====================================

            elif choice == "19":

                save_history(
                    "vendor_detection",
                    "manual"
                )

                network.vendor_lookup()

            # =====================================
            # INTERNET SPEED TEST
            # =====================================

            elif choice == "22":

                save_history(
                    "speed_test",
                    "internet"
                )

                network.speed_test()

            # =====================================
            # TECHNOLOGY DETECTION
            # =====================================

            elif choice == "26":

                save_history(
                    "technology_detection",
                    "website"
                )

                network.detect_technology()

            # =====================================
            # SCAN HISTORY
            # =====================================

            elif choice == "29":

                show_history()

            # =====================================
            # EXIT
            # =====================================

            elif choice == "0":

                console.print(
                    "\n[bold red]Exiting NetScan...[/bold red]"
                )

                console.print(
                    "[bold cyan]Goodbye![/bold cyan]\n"
                )

                raise SystemExit

            # =====================================
            # INVALID OPTION
            # =====================================

            else:

                console.print(
                    "[bold red]Invalid Option[/bold red]"
                )

            # =====================================
            # CONTINUE
            # =====================================

            Prompt.ask(
                "\n[cyan]Press Enter To Continue[/cyan]"
            )

        # =========================================
        # CTRL + C
        # =========================================

        except KeyboardInterrupt:

            console.print(
                "\n[bold red]Interrupted By User[/bold red]"
            )

            raise SystemExit

        # =========================================
        # EXCEPTION
        # =========================================

        except Exception:

            console.print_exception()

            Prompt.ask(
                "\n[cyan]Press Enter To Continue[/cyan]"
            )

# =========================================
# START
# =========================================

if __name__ == "__main__":

    main()