#!/usr/bin/env python
import socket
import os
import sys
import concurrent.futures
from colorama import Fore, Style, init

# Colorama Auto-reset
init(autoreset=True)

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def display_banner():
    clear_screen()
    print(Fore.CYAN + Style.BRIGHT + r"""
     _   _      _   ____                  
    | \ | | ___| |_/ ___|  ___ __ _ _ __  
    |  \| |/ _ \ __\___ \ / __/ _` | '_ \ 
    | |\  |  __/ |_ ___) | (_| (_| | | | |
    |_| \_|\___|\__|____/ \___\__,_|_| |_|
    """)
    print(Fore.YELLOW + "      Advanced Termux Network Scanner")
    print(Fore.WHITE + "      -------------------------------\n")

def scan_port(target_ip, port, open_ports):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5) # Fast timeout for quick scanning
        result = s.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append(port)
        s.close()
    except:
        pass

def port_scanner():
    target = input(Fore.GREEN + "Enter Target IP or Domain (e.g., 192.168.1.1): " + Style.RESET_ALL)
    try:
        target_ip = socket.gethostbyname(target)
        print(Fore.BLUE + f"\n[*] Target Resolved: {target_ip}")
    except socket.gaierror:
        print(Fore.RED + "\n[!] Invalid Hostname or IP Address.")
        input(Fore.YELLOW + "\nPress Enter to return to menu...")
        return

    print(Fore.YELLOW + "[*] Scanning Top 1024 Ports... Please wait.\n")
    open_ports = []
    
    # 100 টি থ্রেড ব্যবহার করে দ্রুত স্ক্যানিং
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, target_ip, port, open_ports): port for port in range(1, 1025)}
        for future in concurrent.futures.as_completed(futures):
            pass # Wait for all threads to finish

    if open_ports:
        print(Fore.GREEN + Style.BRIGHT + "--- 🔓 OPEN PORTS FOUND ---")
        for port in sorted(open_ports):
            print(Fore.CYAN + f"[+] Port {port} is OPEN")
    else:
        print(Fore.RED + "[-] No open ports found on target.")
    
    input(Fore.YELLOW + "\nPress Enter to return to menu...")

def get_my_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        ip_addr = s.getsockname()[0]
    except Exception:
        ip_addr = '127.0.0.1'
    finally:
        s.close()
        
    print(Fore.GREEN + Style.BRIGHT + f"\n[+] Your Local Network IP is: {ip_addr}")
    input(Fore.YELLOW + "\nPress Enter to return to menu...")

def main():
    while True:
        display_banner()
        print(Fore.WHITE + "1. Find My Local IP Address")
        print(Fore.WHITE + "2. Scan Target for Open Ports")
        print(Fore.WHITE + "3. Exit\n")
        
        choice = input(Fore.GREEN + "Select an option (1/2/3): " + Style.RESET_ALL)
        
        if choice == '1':
            get_my_ip()
        elif choice == '2':
            port_scanner()
        elif choice == '3':
            print(Fore.RED + "\n[!] Exiting NetScan... Good bye!\n")
            sys.exit()
        else:
            print(Fore.RED + "\n[!] Invalid choice! Try again.")
            import time
            time.sleep(1)

if __name__ == '__main__':
    # ইন্টারাপ্ট (Ctrl+C) হ্যান্ডেল করার জন্য
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n\n[!] Program interrupted by user. Exiting...\n")
        sys.exit()