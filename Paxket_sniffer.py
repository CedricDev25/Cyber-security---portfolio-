==============================================
  NETWORK PACKET SNIFFER
  Cybersecurity Portfolio Tool
  Author: Shyaka Imena Cedric
  GitHub: github.com/YOUR_USERNAME
  Description: Captures and analyzes live network
               traffic using Scapy. Detects:
               - HTTP traffic & credentials in plaintext
               - DNS queries (domain lookups)
               - Port scan signatures
               - ARP spoofing attempts
               - SYN flood indicators

  REQUIREMENTS: pip install scapy
  USAGE: sudo python3 packet_sniffer.py
  ⚠️  Run only on your own network!
==============================================
"""

import sys
import argparse
import signal
from collections import defaultdict, Counter
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, ARP, Raw, Ether
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    print("\n[ERROR] Scapy not installed.")
    print("  Run: pip install scapy")
    sys.exit(1)


# ──────────────────────────────────────────
# STATE
# ──────────────────────────────────────────
stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "dns_queries": [],
    "http_requests": [],
    "credentials": [],
    "arp_table": {},
    "syn_counts": defaultdict(int),
    "port_scan_suspects": defaultdict(set),
    "alerts": [],
}

PACKET_LIMIT = 0  # 0 = unlimited (set via --count)


# ──────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────
def timestamp():
    return datetime.now().strftime("%H:%M:%S")


def alert(level, msg):
    icon = {"HIGH": "🔴", "MEDIUM": "🟡", "INFO": "🔵"}.get(level, "⚪")
    line = f"  {icon} [{timestamp()}] [{level}] {msg}"
    stats["alerts"].append(line)
    print(line)


# ──────────────────────────────────────────
# PACKET HANDLERS
# ──────────────────────────────────────────
def handle_dns(packet):
    """Log DNS queries — reveals what sites someone is visiting."""
    if packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
        src = packet[IP].src if packet.haslayer(IP) else "?"
        entry = {"time": timestamp(), "src": src, "query": query}
        stats["dns_queries"].append(entry)
        print(f"  🌐 [{timestamp()}] DNS  {src:<18} → {query}")


def handle_http(packet):
    """Detect HTTP requests and sniff for plaintext credentials."""
    if packet.haslayer(HTTPRequest):
        req = packet[HTTPRequest]
        host = req.Host.decode(errors="ignore") if req.Host else ""
        path = req.Path.decode(errors="ignore") if req.Path else ""
        method = req.Method.decode(errors="ignore") if req.Method else ""
        src = packet[IP].src if packet.haslayer(IP) else "?"

        entry = f"  🌍 [{timestamp()}] HTTP {method} {src} → {host}{path}"
        stats["http_requests"].append(entry)
        print(entry)

        # Check for credentials in POST body
        if packet.haslayer(Raw):
            body = packet[Raw].load.decode(errors="ignore")
            keywords = ["password", "passwd", "pass", "pwd", "username", "user", "login", "email"]
            for kw in keywords:
                if kw in body.lower():
                    cred_line = f"  🚨 [{timestamp()}] CREDENTIAL FOUND from {src} on {host}: {body[:100]}"
                    stats["credentials"].append(cred_line)
                    alert("HIGH", f"Plaintext credential from {src} to {host}")
                    break


def handle_arp(packet):
    """Detect ARP spoofing (IP-MAC conflicts)."""
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        if ip in stats["arp_table"]:
            if stats["arp_table"][ip] != mac:
                alert("HIGH", f"ARP SPOOFING detected! {ip} changed from {stats['arp_table'][ip]} to {mac}")
        else:
            stats["arp_table"][ip] = mac


def handle_syn_flood(packet):
    """Detect potential SYN flood (DoS indicator)."""
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        if flags == 0x002:  # SYN flag only
            src = packet[IP].src if packet.haslayer(IP) else "?"
            stats["syn_counts"][src] += 1
            if stats["syn_counts"][src] == 50:
                alert("HIGH", f"Possible SYN FLOOD from {src} ({stats['syn_counts'][src]} SYN packets)")


def handle_port_scan(packet):
    """Detect port scanning behavior (many ports from same IP)."""
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src = packet[IP].src
        dst_port = packet[TCP].dport
        stats["port_scan_suspects"][src].add(dst_port)

        count = len(stats["port_scan_suspects"][src])
        if count in (20, 50, 100):  # Alert at thresholds
            alert("MEDIUM", f"Port scan from {src} — {count} unique ports targeted")


# ──────────────────────────────────────────
# MASTER PACKET PROCESSOR
# ──────────────────────────────────────────
def process_packet(packet):
    stats["total"] += 1

    if packet.haslayer(TCP):
        stats["tcp"] += 1
        handle_syn_flood(packet)
        handle_port_scan(packet)

    if packet.haslayer(UDP):
        stats["udp"] += 1

    if packet.haslayer(DNS):
        handle_dns(packet)

    if packet.haslayer(HTTPRequest):
        handle_http(packet)

    if packet.haslayer(ARP):
        handle_arp(packet)

    # Live progress
    if stats["total"] % 50 == 0:
        print(f"\n  📊 Packets: {stats['total']} │ TCP: {stats['tcp']} │ UDP: {stats['udp']} │ DNS: {len(stats['dns_queries'])} │ Alerts: {len(stats['alerts'])}\n")


# ──────────────────────────────────────────
# FINAL REPORT
# ──────────────────────────────────────────
def print_summary():
    print("\n\n" + "═" * 65)
    print("  SESSION SUMMARY — CEDRIC'S PACKET SNIFFER")
    print("═" * 65)
    print(f"  Total packets captured : {stats['total']}")
    print(f"  TCP packets            : {stats['tcp']}")
    print(f"  UDP packets            : {stats['udp']}")
    print(f"  DNS queries            : {len(stats['dns_queries'])}")
    print(f"  HTTP requests          : {len(stats['http_requests'])}")
    print(f"  Credentials detected   : {len(stats['credentials'])}")
    print(f"  ARP entries            : {len(stats['arp_table'])}")
    print(f"  Alerts raised          : {len(stats['alerts'])}")

    if stats["dns_queries"]:
        print(f"\n{'─'*65}")
        print("  TOP DNS QUERIES")
        print(f"{'─'*65}")
        domains = Counter(q["query"] for q in stats["dns_queries"])
        for domain, count in domains.most_common(10):
            print(f"  {count:>4}x  {domain}")

    if stats["credentials"]:
        print(f"\n{'─'*65}")
        print("  ⚠️  CREDENTIALS INTERCEPTED")
        print(f"{'─'*65}")
        for c in stats["credentials"]:
            print(c)

    if stats["alerts"]:
        print(f"\n{'─'*65}")
        print("  ALL ALERTS")
        print(f"{'─'*65}")
        for a in stats["alerts"]:
            print(a)

    print("\n" + "═" * 65 + "\n")


# ──────────────────────────────────────────
# GRACEFUL SHUTDOWN
# ──────────────────────────────────────────
def signal_handler(sig, frame):
    print("\n\n  [*] Stopping capture...")
    print_summary()
    sys.exit(0)


# ──────────────────────────────────────────
# CLI & MAIN
# ──────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Cedric's Packet Sniffer — Analyze live network traffic",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-i", "--iface", default=None, help="Network interface (e.g. eth0, wlan0). Default: auto")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter", default="", help='BPF filter (e.g. "tcp port 80", "udp")')
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)

    print("\n" + "═" * 65)
    print("  CEDRIC'S NETWORK PACKET SNIFFER")
    print("═" * 65)
    print(f"  Interface : {args.iface or 'auto-detect'}")
    print(f"  Filter    : {args.filter or 'none (capture all)'}")
    print(f"  Count     : {args.count or 'unlimited'}")
    print(f"  Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("═" * 65)
    print("  ⚠️  Only use on networks you own or have permission to monitor.")
    print("  Press Ctrl+C to stop and see the summary.\n")

    sniff(
        iface=args.iface,
        filter=args.filter,
        prn=process_packet,
        count=args.count,
        store=False
    )

    print_summary()
