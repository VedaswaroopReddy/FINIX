"""
tests/test_redos_and_siem.py: Tests for ReDoS Immunity Benchmark and SIEM Multi-Pattern Log Scanner.
"""

import os
import pytest
from regex_nfa import (
    ReDoSBenchmarkSuite,
    BENCHMARK_TAXONOMIES,
    SIEMRule,
    MasterSecurityDFA,
    SIEMLogScanner,
)


class TestReDoSImmunityHarness:
    """Verifies that FINIX delivers linear-time execution across ReDoS taxonomies."""

    def test_benchmark_taxonomies_available(self):
        assert len(BENCHMARK_TAXONOMIES) >= 4
        ids = [t["id"] for t in BENCHMARK_TAXONOMIES]
        assert "TAXONOMY_1" in ids
        assert "TAXONOMY_2" in ids

    def test_benchmark_run_short_lengths(self):
        suite = ReDoSBenchmarkSuite(timeout_sec=0.5)
        # Test on modest lengths for rapid unit test execution
        results = suite.run_benchmark(taxonomy_id="TAXONOMY_1", lengths=[6, 10, 14])

        assert "data_points" in results
        assert len(results["data_points"]) == 3

        for dp in results["data_points"]:
            assert dp["finix_nfa_ms"] < 20.0  # Strict SLA
            assert dp["finix_dfa_ms"] < 5.0   # Strict SLA

        assert "ascii_table" in results
        assert "svg_chart" in results
        assert "<svg" in results["svg_chart"]

    def test_extreme_scalability_finix_dfa(self):
        """Proves FINIX DFA matches 5,000 characters without crashing or stalling."""
        suite = ReDoSBenchmarkSuite()
        tax = BENCHMARK_TAXONOMIES[0]
        from regex_nfa.dfa import compile_to_dfa
        min_dfa = compile_to_dfa(tax["pattern"]).minimize()

        # 5,000 repeated 'a' characters
        evil_payload = "a" * 5000
        import time
        t0 = time.perf_counter()
        verdict = min_dfa.match(evil_payload)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        # Must reject (missing 'b') in under 15 milliseconds
        assert verdict is False
        assert elapsed_ms < 15.0, f"DFA took {elapsed_ms:.2f}ms on n=5000 (SLA < 15ms)"


class TestSIEMMultiPatternScanner:
    """Verifies multi-signature compilation, master DFA determinization, and log scanning."""

    @pytest.fixture
    def scanner(self):
        rules_path = os.path.join(os.path.dirname(__file__), "..", "rules", "security_signatures.json")
        return SIEMLogScanner(rules_json_path=rules_path)

    def test_rules_loaded(self, scanner):
        assert len(scanner.rules) >= 10
        rule_ids = [r.id for r in scanner.rules]
        assert "SEC-SQLI-01" in rule_ids
        assert "SEC-XSS-01" in rule_ids
        assert "SEC-TRAV-01" in rule_ids

    def test_detect_sql_injection_log(self, scanner):
        log_line = '192.168.1.100 - - [20/Oct/2026:12:00:00 +0000] "GET /items.php?id=1\' or 1=1 HTTP/1.1" 200 4520'
        incident = scanner.scan_line(log_line, line_no=42)

        assert incident is not None
        assert incident.ip == "192.168.1.100"
        assert incident.status_code == 200
        assert incident.highest_threat == "CRITICAL"
        matched_ids = [r.id for r in incident.matched_rules]
        assert "SEC-SQLI-01" in matched_ids

    def test_detect_path_traversal_log(self, scanner):
        log_line = '10.0.0.5 - - [20/Oct/2026:12:01:00 +0000] "GET /static/../../etc/passwd HTTP/1.1" 404 120'
        incident = scanner.scan_line(log_line, line_no=43)

        assert incident is not None
        matched_ids = [r.id for r in incident.matched_rules]
        assert "SEC-TRAV-01" in matched_ids or "SEC-CRED-01" in matched_ids

    def test_detect_xss_injection_log(self, scanner):
        log_line = '172.16.0.2 - - [20/Oct/2026:12:02:00 +0000] "GET /profile?name=<script>alert(1)</script> HTTP/1.1" 200 890'
        incident = scanner.scan_line(log_line, line_no=44)

        assert incident is not None
        matched_ids = [r.id for r in incident.matched_rules]
        assert "SEC-XSS-01" in matched_ids

    def test_clean_request_not_flagged(self, scanner):
        clean_line = '192.168.1.50 - - [20/Oct/2026:12:05:00 +0000] "GET /assets/style.css HTTP/1.1" 200 12400'
        incident = scanner.scan_line(clean_line, line_no=45)
        assert incident is None

    def test_batch_scan_report_metrics(self, scanner):
        sample_logs = [
            '192.168.1.1 - - [20/Oct/2026:12:10:00 +0000] "GET /index.html HTTP/1.1" 200 5000',
            '192.168.1.2 - - [20/Oct/2026:12:10:01 +0000] "GET /login?user=\' or 1=1 HTTP/1.1" 401 230',
            '192.168.1.3 - - [20/Oct/2026:12:10:02 +0000] "GET /about.html HTTP/1.1" 200 4500',
            '192.168.1.4 - - [20/Oct/2026:12:10:03 +0000] "GET /download/malware.exe HTTP/1.1" 200 90000',
            '192.168.1.5 - - [20/Oct/2026:12:10:04 +0000] "GET /images/logo.png HTTP/1.1" 200 12000'
        ]

        report = scanner.scan_lines(sample_logs)

        assert report["total_lines_scanned"] == 5
        assert report["incidents_detected"] >= 2
        assert report["clean_requests"] <= 3
        assert report["throughput_lines_per_sec"] > 50.0
        assert "threat_breakdown" in report
        assert "category_breakdown" in report
