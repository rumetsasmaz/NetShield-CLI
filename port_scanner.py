import socket

def scan_port_and_banner(target, start_port, end_port):
    """
    Scans a specified port range for a given target IP/Domain
    and performs Banner Grabbing (Service Discovery) on open ports.
    """
    print(f"\n[+] NetShield Scanner started: {target}")
    print(f"[+] Target Port Range: {start_port} - {end_port}")
    print("=" * 50)

    # Resolve domain name to IP if a hostname was provided
    try:
        target_ip = socket.gethostbyname(target)
        if target != target_ip:
            print(f"[*] Target IP: {target_ip}")
    except socket.gaierror:
        print(f"[-] Error: Could not resolve '{target}'. Please enter a valid IP or Domain.")
        return

    open_ports_count = 0

    for port in range(start_port, end_port + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)  # Connection timeout limit

        try:
            result = s.connect_ex((target_ip, port))

            if result == 0:
                open_ports_count += 1
                print(f"[SUCCESS] Port {port}: OPEN")
                
                # Banner Grabbing Attempt
                try:
                    # HTTP & Generic trigger payload
                    s.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    
                    if banner:
                        # Grab the first line of the response
                        banner_summary = banner.split('\n')[0]
                        print(f"   └── [BANNER]: {banner_summary}")
                    else:
                        print(f"   └── [BANNER]: No response / Silent service.")
                except:
                    print(f"   └── [BANNER]: Failed to retrieve banner payload.")

        except Exception:
            pass
        finally:
            s.close()

    print("=" * 50)
    print(f"[+] Scan Finished. Total Open Ports: {open_ports_count}\n")


def run_scanner_ui():
    """Interactive CLI Interface to be called from NetShield Main Menu."""
    print("\n--- NetShield-CLI :: Port & Service Scanner ---")
    target = input("Target IP or Domain (e.g., 127.0.0.1): ").strip()
    
    if not target:
        print("[-] Error: Target cannot be empty!")
        return

    try:
        start_port = int(input("Start Port (e.g., 1): "))
        end_port = int(input("End Port (e.g., 1000): "))

        if start_port > end_port or start_port < 1 or end_port > 65535:
            print("[-] Error: Invalid port range! Must be between 1 and 65535.")
            return

        scan_port_and_banner(target, start_port, end_port)

    except ValueError:
        print("[-] Error: Port numbers must be integers!")


if __name__ == "__main__":
    # Direct test run
    run_scanner_ui()