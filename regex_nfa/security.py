"""
security.py: First-Principles Security Signature Engine & Live Traffic Scanner.
Applies Thompson's ε-NFA to detect malicious URLs, payloads, and file patterns.
"""

from typing import List, Dict, Any
from .thompson import compile_regex
from .simulator import NFASimulator, SimulationResult


class SecurityRule:
    """Represents a formal security signature defined via a regular expression."""
    def __init__(self, rule_id: str, name: str, pattern: str, threat_level: str,
                 category: str, description: str):
        self.id = rule_id
        self.name = name
        self.pattern = pattern
        self.threat_level = threat_level.upper()
        self.category = category
        self.description = description
        self.nfa = compile_regex(pattern)
        self.simulator = NFASimulator(self.nfa)

    def evaluate(self, payload: str) -> SimulationResult:
        """Evaluates a single target payload against this security pattern."""
        return self.simulator.simulate(payload)


class SecurityScanReport:
    """Encapsulates the verdict and matched signatures for a scanned string."""
    def __init__(self, target: str):
        self.target = target
        self.matches: List[Dict[str, Any]] = []

    @property
    def is_flagged(self) -> bool:
        return len(self.matches) > 0

    @property
    def highest_threat(self) -> str:
        if not self.matches:
            return "SAFE"
        weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return max(self.matches, key=lambda m: weights.get(m["rule"].threat_level, 0))["rule"].threat_level


class SecurityScanner:
    """Manages the signature database and provides high-speed payload scanning."""
    def __init__(self):
        self.rules: List[SecurityRule] = []
        self._load_default_signatures()

    def add_rule(self, rule_id: str, name: str, pattern: str, threat_level: str,
                 category: str, description: str):
        rule = SecurityRule(rule_id, name, pattern, threat_level, category, description)
        self.rules.append(rule)

    def _load_default_signatures(self):
        """Loads default signature rules matching the core engine scope."""
        self.add_rule(
            rule_id="SEC-01",
            name="Executable Download via Web Protocol",
            pattern=r"(http|https)://.*\.exe",
            threat_level="HIGH",
            category="Malware Distribution",
            description="Detects executable binary (.exe) downloads originating over HTTP/HTTPS."
        )
        self.add_rule(
            rule_id="SEC-02",
            name="Insecure Cleartext Transport",
            pattern="http://.*",
            threat_level="MEDIUM",
            category="Transport Security",
            description="Flags cleartext unencrypted HTTP traffic susceptible to interception."
        )
        self.add_rule(
            rule_id="SEC-03",
            name="Privileged Access / Credential Endpoint",
            pattern=".*(login|admin|auth|passwd).*",
            threat_level="HIGH",
            category="Authentication Security",
            description="Identifies sensitive authentication, admin, or credential endpoints."
        )
        self.add_rule(
            rule_id="SEC-04",
            name="Shell Script / Batch Execution",
            pattern=r".*\.(sh|bat|bin)",
            threat_level="CRITICAL",
            category="Remote Code Execution",
            description="Detects execution attempts of command shell scripts and batch files."
        )
        self.add_rule(
            rule_id="SEC-05",
            name="Cross-Site Scripting (XSS) Tag Injection",
            pattern=".*<script>.*",
            threat_level="HIGH",
            category="Web Application Attack",
            description="Flags inline HTML script tag injection attempts in traffic payloads."
        )
        self.add_rule(
            rule_id="SEC-06",
            name="SQL Injection Tautology Signature",
            pattern=r".*' or '.*",
            threat_level="CRITICAL",
            category="Database Security",
            description="Detects classic SQL injection authentication bypass strings (' or ')."
        )

    def scan(self, target: str) -> SecurityScanReport:
        """Scans target payload against all registered signatures."""
        report = SecurityScanReport(target)
        for rule in self.rules:
            result = rule.evaluate(target)
            if result.is_accepted:
                report.matches.append({
                    "rule": rule,
                    "result": result
                })
        return report

    def scan_batch(self, targets: List[str]) -> List[SecurityScanReport]:
        return [self.scan(t) for t in targets]
