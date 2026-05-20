#!/usr/bin/env python3
"""
==============================================
  PORT SCANNER - Cybersecurity Portfolio Tool
  Author: Shyaka Imena Cedric
  GitHub: github.com/YOUR_USERNAME
  Description: A multi-threaded TCP port scanner
               that identifies open ports and
               attempts service banner grabbing.
==============================================
"""

import socket
import threading
import argparse
import sys
from datetime import datetime
from queue import Queue

# ──────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────
MAX_THREADS = 100
TIMEOUT = 1  # seconds per connection attempt
print_lock = threading.Lock()

# Common ports and their known services
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

open_ports = []


# ──────────────────────────────────────────
# BANNER GRABBING
# ──────────────────────────────────────────
def grab_banner(ip, port):
    """Try to grab a service banner for extra info."""
    try:
        sock = socket.socket()
        sock.settimeout(TIMEOUT)
        sock.connect((ip, port))
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner[:80] if banner else None
    except Exception:
        return None


# ──────────────────────────────────────────
# PORT SCANNER CORE
# ──────────────────────────────────────────
def scan_port(ip, port):
    """Attempt TCP connection to a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:  # Port is open
            service = COMMON_SERVICES.get(port, "Unknown")
            banner = grab_banner(ip, port)

            open_ports.append(port)

            with print_lock:
                status = f"  [OPEN]  Port {port:<6} │ {service:<15}"
                if banner:
                    status += f" │ {banner[:50]}"
                print(status)

    except socket.error:
        pass


# ──────────────────────────────────────────
# THREAD WORKER
# ──────────────────────────────────────────
def worker(ip, queue):
    """Thread worker that pulls ports from the queue."""
    while not queue.empty():
        port = queue.get()
        scan_port(ip, port)
        queue.task_done()


# ──────────────────────────────────────────
# RESOLVE HOSTNAME
# ──────────────────────────────────────────
def resolve_host(target):
    """Resolve hostname to IP address."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print(f"\n[ERROR] Cannot resolve host: {target}")
        sys.exit(1)


# ──────────────────────────────────────────
# MAIN SCANNER
# ──────────────────────────────────────────
def run_scan(target, start_port, end_port, threads):
    ip = resolve_host(target)

    print("\n" + "═" * 60)
    print("  CEDRIC'S PORT SCANNER")
    print("═" * 60)
    print(f"  Target   : {target} ({ip})")
    print(f"  Ports    : {start_port} - {end_port}")
    print(f"  Threads  : {threads}")
    print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("═" * 60)
    print()

    # Load ports into queue
    queue = Queue()
    for port in range(start_port, end_port + 1):
        queue.put(port)

    # Spin up threads
    thread_list = []
    for _ in range(min(threads, MAX_THREADS)):
        t = threading.Thread(target=worker, args=(ip, queue))
        t.daemon = True
        thread_list.append(t)
        t.start()

    # Wait for all threads to finish
    queue.join()

    # Summary
    print()
    print("═" * 60)
    print(f"  SCAN COMPLETE")
    print(f"  Open ports found : {len(open_ports)}")
    if open_ports:
        print(f"  Ports            : {sorted(open_ports)}")
    print(f"  Finished         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("═" * 60)


# ──────────────────────────────────────────
# CLI ARGUMENT PARSING
# ──────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="Cedric's Port Scanner - Cybersecurity Portfolio Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target", help="Target IP or hostname (e.g. 192.168.1.1)")
    parser.add_argument("-s", "--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("-e", "--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads (default: 50)")
    return parser.parse_args()


# ──────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────
if __name__ == "__main__":
    print("\n  ⚠️  WARNING: Only scan systems you own or have permission to scan.")
    print("  Unauthorized scanning is illegal.\n")

    args = parse_args()

    if args.start < 1 or args.end > 65535 or args.start > args.end:
        print("[ERROR] Invalid port range. Use 1-65535.")
        sys.exit(1)

    run_scan(args.target, args.start, args.end, args.threads
