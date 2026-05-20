===========================================
  LOG ANALYZER - Cybersecurity Portfolio Tool
  Author: Shyaka Imena Cedric
  GitHub: github.com/YOUR_USERNAME
  Description: Analyzes web server (Apache/Nginx)
               access logs to detect:
               - Brute force login attempts
               - Port/directory scanning behavior
               - Suspicious IPs & user agents
               - 404 flood attacks
==============================================
"""

import re
import argparse
import sys
from collections import defaultdict, Counter
from datetime import datetime

# ──────────────────────────────────────────
# THRESHOLDS (tune these)
# ──────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 10      # Failed logins from same IP
SCAN_THRESHOLD = 20             # 404s from same IP = scanner
HIGH_TRAFFIC_THRESHOLD = 100    # Requests from one IP = suspicious
REPORT_TOP_N = 10               # Show top N results

# ──────────────────────────────────────────
# SUSPICIOUS PATTERNS
# ──────────────────────────────────────────
SUSPICIOUS_PATHS = [
    "/admin", "/wp-admin", "/phpmyadmin", "/.env",
    "/config", "/.git", "/backup", "/shell",
    "/etc/passwd", "/proc/self", "/../", "/cmd",
]

SUSPICIOUS_AGENTS = [
    "sqlmap", "nikto", "nmap", "masscan",
    "zgrab", "gobuster", "dirbuster", "hydra",
    "curl/", "python-requests", "scrapy",
]

# ──────────────────────────────────────────
# LOG PARSER (Apache/Nginx combined format)
# ──────────────────────────────────────────
LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'   # IP address
    r'.*?'                               # ident, user
    r'\[(?P<time>[^\]]+)\]\s+'          # timestamp
    r'"(?P<method>\w+)\s+'              # HTTP method
    r'(?P<path>\S+)\s+'                 # request path
    r'HTTP/[\d.]+"\s+'                  # protocol
    r'(?P<status>\d+)\s+'               # status code
    r'(?P<size>\d+|-)'                  # response size
    r'(?:\s+"[^"]*"\s+"(?P<agent>[^"]*)")?' # user agent
)


def parse_log_line(line):
    match = LOG_PATTERN.match(line.strip())
    if match:
        return match.groupdict()
    return None


# ──────────────────────────────────────────
# ANALYSIS ENGINE
# ──────────────────────────────────────────
class LogAnalyzer:
    def __init__(self):
        self.ip_requests = defaultdict(int)
        self.ip_failures = defaultdict(int)      # 401/403
        self.ip_not_found = defaultdict(int)     # 404s
        self.ip_paths = defaultdict(set)
        self.status_counts = Counter()
        self.path_counts = Counter()
        self.agent_counts = Counter()
        self.suspicious_events = []
        self.total_lines = 0
        self.parse_errors = 0

    def analyze_line(self, line):
        data = parse_log_line(line)
        if not data:
            self.parse_errors += 1
            return

        self.total_lines += 1
        ip = data["ip"]
        status = int(data["status"])
        path = data.get("path", "")
        agent = data.get("agent", "") or ""

        # Count per IP
        self.ip_requests[ip] += 1
        self.ip_paths[ip].add(path)
        self.status_counts[status] += 1
        self.path_counts[path] += 1
        self.agent_counts[agent] += 1

        # Track failures
        if status in (401, 403):
            self.ip_failures[ip] += 1

        # Track 404s
        if status == 404:
            self.ip_not_found[ip] += 1

        # Flag suspicious paths
        for suspicious in SUSPICIOUS_PATHS:
            if suspicious.lower() in path.lower():
                self.suspicious_events.append({
                    "type": "SUSPICIOUS PATH",
                    "ip": ip,
                    "detail": path,
                    "status": status
                })
                break

        # Flag suspicious user agents
        agent_lower = agent.lower()
        for bad_agent in SUSPICIOUS_AGENTS:
            if bad_agent.lower() in agent_lower:
                self.suspicious_events.append({
                    "type": "SCANNER AGENT",
                    "ip": ip,
                    "detail": agent[:60],
                    "status": status
                })
                break

    def get_threats(self):
        threats = []

        # Brute force detection
        for ip, count in self.ip_failures.items():
            if count >= BRUTE_FORCE_THRESHOLD:
                threats.append({
                    "severity": "HIGH",
                    "type": "BRUTE FORCE",
                    "ip": ip,
                    "detail": f"{count} failed auth attempts (401/403)"
                })

        # Directory scanning detection
        for ip, count in self.ip_not_found.items():
            if count >= SCAN_THRESHOLD:
                threats.append({
                    "severity": "MEDIUM",
                    "type": "DIRECTORY SCAN",
                    "ip": ip,
                    "detail": f"{count} requests returned 404"
                })

        # High traffic / DDoS indicator
        for ip, count in self.ip_requests.items():
            if count >= HIGH_TRAFFIC_THRESHOLD:
                threats.append({
                    "severity": "MEDIUM",
                    "type": "HIGH TRAFFIC",
                    "ip": ip,
                    "detail": f"{count} total requests"
                })

        return sorted(threats, key=lambda x: ("HIGH", "MEDIUM", "LOW").index(x["severity"]))


# ──────────────────────────────────────────
# REPORT PRINTER
# ──────────────────────────────────────────
def print_report(analyzer, filename):
    threats = analyzer.get_threats()

    print("\n" + "═" * 65)
    print("  CEDRIC'S LOG ANALYZER - SECURITY REPORT")
    print("═" * 65)
    print(f"  File     : {filename}")
    print(f"  Lines    : {analyzer.total_lines:,}")
    print(f"  Errors   : {analyzer.parse_errors:,} unparseable lines")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("═" * 65)

    # ── THREAT SUMMARY ──
    print(f"\n{'━'*65}")
    print(f"  🚨 THREATS DETECTED ({len(threats)})")
    print(f"{'━'*65}")
    if threats:
        for t in threats:
            icon = "🔴" if t["severity"] == "HIGH" else "🟡"
            print(f"  {icon} [{t['severity']}] {t['type']:<18} │ IP: {t['ip']:<16} │ {t['detail']}")
    else:
        print("  ✅ No major threats detected.")

    # ── SUSPICIOUS EVENTS ──
    if analyzer.suspicious_events:
        print(f"\n{'━'*65}")
        print(f"  ⚠️  SUSPICIOUS EVENTS ({len(analyzer.suspicious_events)})")
        print(f"{'━'*65}")
        seen = set()
        for e in analyzer.suspicious_events[:20]:  # limit output
            key = (e["type"], e["ip"], e["detail"])
            if key not in seen:
                seen.add(key)
                print(f"  [{e['type']}] IP: {e['ip']:<16} │ {e['detail']}")

    # ── TOP IPs ──
    print(f"\n{'━'*65}")
    print(f"  📊 TOP {REPORT_TOP_N} IPs BY REQUEST COUNT")
    print(f"{'━'*65}")
    for ip, count in sorted(analyzer.ip_requests.items(), key=lambda x: -x[1])[:REPORT_TOP_N]:
        bar = "█" * min(count // 10, 30)
        print(f"  {ip:<18} {count:>6} requests  {bar}")

    # ── STATUS CODE BREAKDOWN ──
    print(f"\n{'━'*65}")
    print(f"  📈 HTTP STATUS CODE BREAKDOWN")
    print(f"{'━'*65}")
    for status, count in sorted(analyzer.status_counts.items()):
        label = {200: "OK", 301: "Redirect", 302: "Redirect",
                 400: "Bad Request", 401: "Unauthorized",
                 403: "Forbidden", 404: "Not Found",
                 500: "Server Error"}.get(status, "")
        print(f"  {status} {label:<15} : {count:,}")

    # ── TOP PATHS ──
    print(f"\n{'━'*65}")
    print(f"  🔍 TOP {REPORT_TOP_N} REQUESTED PATHS")
    print(f"{'━'*65}")
    for path, count in analyzer.path_counts.most_common(REPORT_TOP_N):
        print(f"  {count:>6}x  {path[:60]}")

    print("\n" + "═" * 65)
    print("  SCAN COMPLETE — Stay Secure 🔐")
    print("═" * 65 + "\n")


# ──────────────────────────────────────────
# GENERATE SAMPLE LOG (for testing)
# ──────────────────────────────────────────
def generate_sample_log(filename="sample.log"):
    """Creates a fake Apache log for demo/testing purposes."""
    import random

    normal_ips = ["41.186.10.2", "196.46.8.5", "102.23.14.7"]
    attacker_ip = "185.220.101.45"
    scanner_ip = "45.33.32.156"

    paths = ["/", "/index.html", "/about", "/contact", "/login", "/api/data"]
    scan_paths = ["/admin", "/wp-admin", "/.env", "/phpmyadmin", "/shell.php", "/.git/config"]

    lines = []
    agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    bad_agent = 'sqlmap/1.7.8'
    scan_agent = 'gobuster/3.1.0'

    for _ in range(200):
        ip = random.choice(normal_ips)
        path = random.choice(paths)
        lines.append(f'{ip} - - [10/May/2026:12:00:00 +0000] "GET {path} HTTP/1.1" 200 1024 "-" "{agent}"')

    for _ in range(15):  # brute force
        lines.append(f'{attacker_ip} - - [10/May/2026:12:01:00 +0000] "POST /login HTTP/1.1" 401 512 "-" "{bad_agent}"')

    for path in scan_paths * 5:  # directory scan
        lines.append(f'{scanner_ip} - - [10/May/2026:12:02:00 +0000] "GET {path} HTTP/1.1" 404 256 "-" "{scan_agent}"')

    with open(filename, "w") as f:
        f.write("\n".join(lines))

    print(f"[+] Sample log created: {filename} ({len(lines)} lines)")
    return filename


# ──────────────────────────────────────────
# CLI
# ──────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cedric's Log Analyzer - Detect threats in web server logs")
    parser.add_argument("logfile", nargs="?", help="Path to log file (Apache/Nginx combined format)")
    parser.add_argument("--demo", action="store_true", help="Generate a sample log and run analysis on it")
    args = parser.parse_args()

    if args.demo:
        logfile = generate_sample_log("sample_access.log")
    elif args.logfile:
        logfile = args.logfile
    else:
        parser.print_help()
        sys.exit(1)

    print(f"\n[*] Analyzing: {logfile}")
    analyzer = LogAnalyzer()

    try:
        with open(logfile, "r", errors="ignore") as f:
            for line in f:
                analyzer.analyze_line(line)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {logfile}")
        sys.exit(1)

    print_report(analyzer, logfile)
