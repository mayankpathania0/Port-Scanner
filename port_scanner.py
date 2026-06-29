#!/usr/bin/env python3
"""
Advanced Multi-Threaded Port Scanner with Banner Grabbing
Author: Your Name
Purpose: A fast, flexible network reconnaissance tool for cybersecurity students.
"""

import socket
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 1. CONSTANTS & CONFIGURATION ---
# These are the most frequently attacked or used ports on the internet.
# Scanning these saves time instead of scanning all 65,535 ports.
COMMON_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP (Email)
    53,    # DNS
    80,    # HTTP (Web)
    110,   # POP3 (Email)
    135,   # RPC
    139,   # NetBIOS
    143,   # IMAP (Email)
    443,   # HTTPS (Secure Web)
    445,   # SMB (File Sharing)
    993,   # IMAPS (Secure Email)
    995,   # POP3S (Secure Email)
    1433,  # MSSQL (Database)
    1723,  # PPTP (VPN)
    3306,  # MySQL (Database)
    3389,  # RDP (Remote Desktop)
    5900,  # VNC (Remote Desktop)
    6379,  # Redis (Database)
    8080,  # HTTP-Alt (Proxy/Web)
    8443   # HTTPS-Alt (Secure Web)
]

# --- 2. BANNER GRABBING FUNCTION ---
def grab_banner(ip, port):
    """
    Connects to an OPEN port and tries to read the service's welcome banner.
    This tells us exactly WHAT is running (e.g., 'Apache 2.4.49' or 'OpenSSH 8.9').
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)  # Give the service 2 seconds to respond
        
        # Connect to the open port
        sock.connect((ip, port))
        
        # We need to send a probe to wake up the service.
        # Different services respond to different commands.
        if port in [80, 443, 8080, 8443]:  # Web servers
            # Send an HTTP HEAD request to get the server version
            request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
            sock.send(request.encode())
        else:  # All other services (SSH, FTP, SMTP, etc.)
            # Send a generic 'HELP' or newline to trigger a response
            sock.send(b"\r\n")
        
        # Receive up to 256 bytes of the banner and clean it up
        banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
        # Replace newlines with spaces to keep it on one line
        banner = banner.replace('\n', ' ').replace('\r', ' ')
        # Remove multiple spaces
        banner = ' '.join(banner.split())
        
        sock.close()
        return banner if banner else "[No banner received]"
    
    except socket.timeout:
        return "[Timeout - Service did not respond]"
    except ConnectionRefusedError:
        return "[Connection refused]"
    except Exception:
        return "[Error grabbing banner]"

# --- 3. SINGLE PORT SCANNER (The Worker) ---
def scan_single_port(ip, port):
    """
    This is the 'worker' function that runs in a separate thread.
    It tries to connect to a specific IP:Port.
    If successful (result == 0), the port is OPEN.
    """
    try:
        # AF_INET = IPv4, SOCK_STREAM = TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set a timeout so we don't get stuck on closed ports forever.
        # 0.5 seconds is a good balance between speed and reliability.
        sock.settimeout(0.5)
        
        # connect_ex() returns an error code. 0 means success (port is OPEN).
        result = sock.connect_ex((ip, port))
        
        # Always close the socket to free up system resources
        sock.close()
        
        # If result is 0, the port is open. Return the port number.
        return port if result == 0 else None
    
    except socket.gaierror:
        # This happens if the domain name doesn't exist (e.g., 'fakewebsite.com')
        print(f"[!] Error: Invalid hostname or IP address '{ip}'")
        sys.exit(1)
    except Exception:
        # Catch-all for any other network errors
        return None

# --- 4. THE MAIN SCANNER (The Manager) ---
def scan_ports(target_ip, ports, grab_banners=False):
    """
    Manages the multi-threading.
    It dispatches the scanning work across a pool of worker threads.
    """
    open_ports = []  # List to store ports that are open
    
    print(f"[*] Starting scan on target: {target_ip}")
    print(f"[*] Scanning {len(ports)} ports using multi-threading (50 workers)...")
    print("-" * 50)
    
    # ThreadPoolExecutor creates a pool of threads.
    # max_workers=50 means up to 50 ports are scanned at the exact same time.
    with ThreadPoolExecutor(max_workers=50) as executor:
        # Submit ALL tasks to the executor.
        # This creates a dictionary mapping the 'future' object to the port number.
        future_to_port = {
            executor.submit(scan_single_port, target_ip, port): port 
            for port in ports
        }
        
        # as_completed yields futures as they finish (not in order).
        for future in as_completed(future_to_port):
            port = future_to_port[future]  # Get the port number
            try:
                result = future.result()  # Get the result from the worker
                
                if result is not None:  # If a port number was returned (it's open)
                    print(f"  [+] Port {port} is OPEN")
                    open_ports.append(port)
                    
                    # If the user wants banners, grab it right now
                    if grab_banners:
                        banner = grab_banner(target_ip, port)
                        print(f"      └─ Service info: {banner}")
            
            except Exception as e:
                # If a thread crashes, we just skip it so the whole program doesn't break
                pass
    
    return open_ports

# --- 5. COMMAND-LINE ARGUMENT PARSING ---
def main():
    """
    Parses command-line arguments (e.g., 'python scanner.py 127.0.0.1 -p 1-1000')
    and starts the scan.
    """
    parser = argparse.ArgumentParser(
        description="Fast Multi-Threaded TCP Port Scanner with Banner Grabbing",
        epilog="Example: python port_scanner.py 192.168.1.1 -p common --banners"
    )
    
    # Positional argument: the target IP or hostname
    parser.add_argument("target", help="Target IP address or hostname (e.g., 192.168.1.1 or google.com)")
    
    # Optional argument: which ports to scan
    parser.add_argument(
        "-p", "--ports",
        help="Ports to scan. Use 'common' for top 22 ports, '1-1000' for a range, or '22,80,443' for a list.",
        default="common"
    )
    
    # Optional flag: whether to grab banners
    parser.add_argument(
        "--banners", 
        action="store_true",  # If used, this becomes 'True'
        help="Attempt to grab service banners from open ports (slower but more detailed)"
    )
    
    # Optional flag: quiet mode (if you don't want to see live updates, just the summary)
    # I won't implement quiet mode here for simplicity, but it's a good feature to add later.

    args = parser.parse_args()

    # --- 6. PARSE THE PORTS ARGUMENT ---
    if args.ports.lower() == "common":
        ports_to_scan = COMMON_PORTS
    elif '-' in args.ports:
        # Example: "1-1000" -> split, convert to int, create a range
        try:
            start, end = args.ports.split('-')
            start = int(start)
            end = int(end)
            if start > end:
                print("[!] Error: Start port cannot be greater than end port.")
                sys.exit(1)
            ports_to_scan = list(range(start, end + 1))
        except ValueError:
            print("[!] Error: Invalid port range format. Use '1-1000'.")
            sys.exit(1)
    else:
        # Example: "22,80,443" -> split by comma, convert each to int
        try:
            ports_to_scan = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print("[!] Error: Invalid port list. Use commas like '22,80,443'.")
            sys.exit(1)

    # --- 7. VALIDATE THE TARGET ---
    # Very basic validation: check if it looks like an IP or hostname
    target = args.target.strip()
    if not target:
        print("[!] Error: Target cannot be empty.")
        sys.exit(1)

    # --- 8. EXECUTE THE SCAN ---
    open_ports = scan_ports(target, ports_to_scan, grab_banners=args.banners)

    # --- 9. PRINT THE FINAL SUMMARY ---
    print("-" * 50)
    if open_ports:
        print(f"[✅] Scan Complete! Found {len(open_ports)} open ports: {sorted(open_ports)}")
    else:
        print("[❌] No open ports found on the target in the specified range.")
    print("=" * 50)

# --- 10. STANDARD PYTHON ENTRY POINT ---
if __name__ == "__main__":
    main()
