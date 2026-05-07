#!/usr/bin/env python
import socket
import os
import sys
import concurrent.futures
import requests
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
    print(Fore.YELLOW + "      Advanced Termux Network Toolkit v2.0")
    print(Fore.WHITE + "      ------------------------------------\n")

def get_target_ip():
    target = input(Fore.GREEN + "\nEnter Target IP or Domain (e.g., google.com or 192.168.1.1): " + Style.RESET_ALL)
    try:
        target_ip = socket.gethostbyname(target)
        print(Fore.BLUE + f"[*] Target Resolved: {target_ip}")
        return target, target_ip
    except socket.gaierror:
        print(Fore.RED + "[!] Invalid Hostname or IP Address.")
        return None, None

def scan_port(target_ip, port, open_ports):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append(port)
        s.close()
    except:
        pass

def run_port_scanner(target_ip, start_port, end_port):
    print(Fore.YELLOW + f"\n[*] Scanning Ports from {start_port} to {end_port}... Please wait.\n")
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, target_ip, port, open_ports): port for port in range(start_port, end_port + 1)}
        for future in concurrent.futures.as_completed(futures):
            pass

    if open_ports:
        print(Fore.GREEN + Style.BRIGHT + "--- 🔓 OPEN PORTS FOUND ---")
        for port in sorted(open_ports):
            print(Fore.CYAN + f"[+] Port {port} is OPEN")
    else:
        print(Fore.RED + "[-] No open ports found.")

def banner_grabbing():
    target, target_ip = get_target_ip()
    if not target_ip: return
    port = input(Fore.GREEN + "Enter Port to grab banner (e.g., 80, 22, 21): " + Style.RESET_ALL)
    try:
        port = int(port)
        print(Fore.YELLOW + f"\n[*] Attempting to grab banner from {target_ip}:{port}...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target_ip, port))
        s.send(b"HEAD / HTTP/1.1\r\n\r\n")
        banner = s.recv(1024).decode().strip()
        print(Fore.CYAN + f"\n[+] Banner Data:\n{banner}")
        s.close()
    except Exception as e:
        print(Fore.RED + f"\n[-] Could not grab banner or port is closed.")

def ip_geolocation():
    target, target_ip = get_target_ip()
    if not target_ip: return
    print(Fore.YELLOW + f"\n[*] Fetching GeoLocation for {target_ip}...")
    try:
        response = requests.get(f"http://ip-api.com/json/{target_ip}").json()
        if response['status'] == 'success':
            print(Fore.CYAN + f"[+] Country: {response.get('country')}")
            print(Fore.CYAN + f"[+] City: {response.get('city')}")
            print(Fore.CYAN + f"[+] ISP: {response.get('isp')}")
            print(Fore.CYAN + f"[+] Lat/Lon: {response.get('lat')} / {response.get('lon')}")
        else:
            print(Fore.RED + "[-] Failed to fetch location.")
    except Exception:
        print(Fore.RED + "[-] Error connecting to GeoLocation API.")

def http_header_grabber():
    target = input(Fore.GREEN + "\nEnter Website URL (e.g., http://example.com): " + Style.RESET_ALL)
    if not target.startswith("http"):
        target = "http://" + target
    print(Fore.YELLOW + f"\n[*] Fetching HTTP Headers for {target}...")
    try:
        response = requests.head(target, timeout=5)
        for key, value in response.headers.items():
            print(Fore.CYAN + f"[+] {key}: {value}")
    except Exception:
        print(Fore.RED + "[-] Failed to connect to the website.")

def dns_lookup():
    target = input(Fore.GREEN + "\nEnter IP or Domain: " + Style.RESET_ALL)
    print(Fore.YELLOW + f"\n[*] Performing DNS Lookup...")
    try:
        ip = socket.gethostbyname(target)
        print(Fore.CYAN + f"[+] Domain to IP: {ip}")
        try:
            host = socket.gethostbyaddr(ip)
            print(Fore.CYAN + f"[+] Reverse DNS (Hostname): {host[0]}")
        except socket.herror:
            print(Fore.RED + "[-] Reverse DNS not found.")
    except socket.gaierror:
        print(Fore.RED + "[-] Invalid Hostname.")

def subdomain_scanner():
    target = input(Fore.GREEN + "\nEnter Domain (e.g., google.com): " + Style.RESET_ALL)
    print(Fore.YELLOW + f"\n[*] Scanning common subdomains... Please wait.")
    subdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'blog', 'shop', 'cpanel']
    found = False
    for sub in subdomains:
        url = f"{sub}.{target}"
        try:
            ip = socket.gethostbyname(url)
            print(Fore.CYAN + f"[+] Found: {url} -> {ip}")
            found = True
        except socket.gaierror:
            pass
    if not found:
        print(Fore.RED + "[-] No common subdomains found.")

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

def main():
    while True:
        display_banner()
        print(Fore.WHITE + " 1. 🌐 Find My Local IP Address")
        print(Fore.WHITE + " 2. ⚡ Fast Port Scan (Top 1024 Ports)")
        print(Fore.WHITE + " 3. 🚀 Full Port Scan (All 65535 Ports)")
        print(Fore.WHITE + " 4. 🎯 Custom Port Range Scan")
        print(Fore.WHITE + " 5. 🛠️  Service Banner Grabbing")
        print(Fore.WHITE + " 6. 🌍 IP GeoLocation Lookup")
        print(Fore.WHITE + " 7. 📜 HTTP Header Grabber")
        print(Fore.WHITE + " 8. 🔍 DNS & Reverse DNS Lookup")
        print(Fore.WHITE + " 9. 🕸️  Basic Subdomain Scanner")
        print(Fore.WHITE + "10. ❌ Exit\n")
        
        choice = input(Fore.GREEN + "Select an option (1-10): " + Style.RESET_ALL)
        
        if choice == '1':
            get_my_ip()
        elif choice == '2':
            target, target_ip = get_target_ip()
            if target_ip: run_port_scanner(target_ip, 1, 1024)
        elif choice == '3':
            target, target_ip = get_target_ip()
            if target_ip: run_port_scanner(target_ip, 1, 65535)
        elif choice == '4':
            target, target_ip = get_target_ip()
            if target_ip:
                start = int(input(Fore.YELLOW + "Enter Start Port: "))
                end = int(input(Fore.YELLOW + "Enter End Port: "))
                run_port_scanner(target_ip, start, end)
        elif choice == '5':
            banner_grabbing()
        elif choice == '6':
            ip_geolocation()
        elif choice == '7':
            http_header_grabber()
        elif choice == '8':
            dns_lookup()
        elif choice == '9':
            subdomain_scanner()
        elif choice == '10':
            print(Fore.RED + "\n[!] Exiting NetScan... Happy Hacking!\n")
            sys.exit()
        else:
            print(Fore.RED + "\n[!] Invalid choice! Try again.")
        
        if choice != '10':
            input(Fore.YELLOW + "\nPress Enter to return to menu...")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n\n[!] Program interrupted by user. Exiting...\n")
        sys.exit()