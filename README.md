# Log Analyzer - Blue Team Tool

[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A simple log parser and analyzer designed to detect suspicious security patterns in system logs. Built for Blue Team practitioners.

## Features

- **Failed login detection** - Identifies failed authentication attempts from multiple log formats
- **Brute force detection** - Flags IPs with excessive failed login attempts
- **Privilege escalation monitoring** - Detects sudo, su, and Windows privilege events
- **Suspicious pattern matching** - Identifies dangerous commands and attack patterns
- **Multiple output formats** - Text (colored), JSON, and CSV
- **Sample data included** - Ready to test out of the box

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
git clone https://github.com/brushi/log-analyzer.git
cd log-analyzer
```

## Usage

### Analyze a log file

```bash
python log_analyzer.py /var/log/auth.log
```

### Run demo mode

```bash
python log_analyzer.py --demo
```

### Export as JSON

```bash
python log_analyzer.py auth.log --format json --output report.json
```

### Export as CSV

```bash
python log_analyzer.py auth.log --format csv --output report.csv
```

### Use sample data

```bash
python log_analyzer.py sample_auth.log
```

### Custom brute force threshold

```bash
python log_analyzer.py auth.log --threshold 3
```

## Project Structure

```
log-analyzer/
├── log_analyzer.py      # Main script
├── sample_auth.log      # Sample log data for testing
├── tests/
│   └── test_log_analyzer.py  # Unit tests
├── pyproject.toml       # Package configuration
├── README.md            # Documentation
├── requirements.txt     # Dependencies (none)
└── LICENSE              # MIT License
```

## Running Tests

```bash
pip install pytest
pytest tests/
```

## License

MIT License - see [LICENSE](LICENSE) for details.
