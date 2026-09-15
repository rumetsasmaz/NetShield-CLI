import socket
from colorama import Fore, Style, init

# Colorama'yı başlatıyoruz (Windows terminal uyumluluğu için)
init(autoreset=True)

# Renk Tanımlamaları
GREEN = Fore.GREEN
RED = Fore.RED
CYAN = Fore.CYAN
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
RESET = Style.RESET_ALL


def scan_port_and_banner(target, start_port, end_port):
    """
    Scans a specified port range for a given target IP/Domain
    and performs Banner Grabbing (Service Discovery) on open ports.
    """
    print(f"\n{CYAN}[+] NetShield Scanner started: {target}{RESET}")
    print(f"{CYAN}[+] Target Port Range: {start_port} - {end_port}{RESET}")
    print("=" * 50)

    # Domain -> IP Dönüşümü
    try:
        target_ip = socket.gethostbyname(target)
        if target != target_ip:
            print(f"{BLUE}[*] Target IP: {target_ip}{RESET}")
    except socket.gaierror:
        print(f"{RED}[-] Error: Could not resolve '{target}'. Please enter a valid IP or Domain.{RESET}")
        return

    open_ports_count = 0

    for port in range(start_port, end_port + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)

        try:
            result = s.connect_ex((target_ip, port))

            if result == 0:
                open_ports_count += 1
                print(f"{GREEN}[SUCCESS] Port {port}: OPEN{RESET}")
                
                # Banner Grabbing
                try:
                    s.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    if banner:
                        banner_summary = banner.split('\n')[0]
                        print(f"   └── {YELLOW}[BANNER]: {banner_summary}{RESET}")
                    else:
                        print(f"   └── {YELLOW}[BANNER]: No response / Silent service.{RESET}")
                except:
                    print(f"   └── {YELLOW}[BANNER]: Failed to retrieve banner payload.{RESET}")

        except Exception:
            pass
        finally:
            s.close()

    print("=" * 50)
    print(f"{GREEN}[+] Scan Finished. Total Open Ports: {open_ports_count}{RESET}\n")


def run_scanner_ui():
    """Interactive CLI Interface to be called from NetShield Main Menu."""
    print(f"\n{CYAN}--- NetShield-CLI :: Port & Service Scanner ---{RESET}")
    target = input(f"{YELLOW}Target IP or Domain (e.g., 127.0.0.1): {RESET}").strip()
    
    if not target:
        print(f"{RED}[-] Error: Target cannot be empty!{RESET}")
        return

    try:
        start_port = int(input(f"{YELLOW}Start Port (e.g., 1): {RESET}"))
        end_port = int(input(f"{YELLOW}End Port (e.g., 1000): {RESET}"))

        if start_port > end_port or start_port < 1 or end_port > 65535:
            print(f"{RED}[-] Error: Invalid port range! Must be between 1 and 65535.{RESET}")
            return

        scan_port_and_banner(target, start_port, end_port)

    except ValueError:
        print(f"{RED}[-] Error: Port numbers must be integers!{RESET}")


if __name__ == "__main__":
    run_scanner_ui()