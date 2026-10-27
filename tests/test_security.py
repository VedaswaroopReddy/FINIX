"""
test_security.py: Security Signature Matching Test Suite.
Validates detection of malicious patterns using first-principles Thompson ε-NFAs.
"""

import unittest
from regex_nfa.security import SecurityScanner, SecurityRule


class TestSecurityScanner(unittest.TestCase):
    """Tests security rules on realistic benign and malicious payloads."""

    def setUp(self):
        self.scanner = SecurityScanner()

    def test_executable_url_rule(self):
        # (http|https)://.*\.exe
        rule = SecurityRule(
            rule_id="TEST-01",
            name="Exe Detector",
            pattern=r"(http|https)://.*\.exe",
            threat_level="HIGH",
            category="Malware",
            description="Executable download"
        )
        # Accepted (Malicious/Suspicious)
        self.assertTrue(rule.evaluate("https://example.com/malware.exe").is_accepted)
        self.assertTrue(rule.evaluate("http://test.org/downloads/payload.exe").is_accepted)
        self.assertTrue(rule.evaluate("https://cdn.site.com/file.exe").is_accepted)

        # Rejected (Safe/Benign)
        self.assertFalse(rule.evaluate("https://example.com/index.html").is_accepted)
        self.assertFalse(rule.evaluate("http://test.org/image.png").is_accepted)
        self.assertFalse(rule.evaluate("ftp://example.com/file.exe").is_accepted)

    def test_insecure_transport_rule(self):
        report = self.scanner.scan("http://insecure-portal.com/login")
        self.assertTrue(report.is_flagged)

    def test_admin_portal_rule(self):
        report = self.scanner.scan("https://bank.com/admin/login")
        self.assertTrue(report.is_flagged)

    def test_script_execution_rule(self):
        report = self.scanner.scan("https://company.org/update.sh")
        self.assertTrue(report.is_flagged)
        self.assertEqual(report.highest_threat, "CRITICAL")

    def test_xss_injection_rule(self):
        report = self.scanner.scan("https://site.com/search?q=<script>alert(1)</script>")
        self.assertTrue(report.is_flagged)

    def test_sql_injection_rule(self):
        report = self.scanner.scan("user' or '1'='1")
        self.assertTrue(report.is_flagged)
        self.assertEqual(report.highest_threat, "CRITICAL")

    def test_clean_payload(self):
        report = self.scanner.scan("https://example.com/about-us")
        self.assertFalse(report.is_flagged)
        self.assertEqual(report.highest_threat, "SAFE")


if __name__ == '__main__':
    unittest.main()
