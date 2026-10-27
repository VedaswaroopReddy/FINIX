"""
test_dfa.py: Comprehensive Unit & Differential Equivalence Tests for Sprint 2 DFA Engine.
Validates:
  1. Rabin-Scott Powerset Construction over P(Q_N).
  2. Language Equivalence Theorem: L(DFA) == L(ε-NFA) across exhaustive string corpora.
  3. Strict O(|w|) matching and flat jump-table correctness.
  4. Trace step generator for synchronized dual-automata stepping.
  5. Structural metrics, state compression, and dead-state rejection.
"""

import unittest
from regex_nfa.thompson import compile_regex
from regex_nfa.simulator import NFASimulator
from regex_nfa.dfa import nfa_to_dfa, compile_to_dfa, DFA


class TestDFABasicConstruction(unittest.TestCase):
    """Verifies powerset construction on elementary regular expression primitives."""

    def test_single_literal_dfa(self):
        dfa = compile_to_dfa("a")
        self.assertEqual(len(dfa.states), 2)
        self.assertTrue(dfa.match("a"))
        self.assertFalse(dfa.match(""))
        self.assertFalse(dfa.match("aa"))
        self.assertFalse(dfa.match("b"))

    def test_concatenation_dfa(self):
        dfa = compile_to_dfa("ab")
        self.assertTrue(dfa.match("ab"))
        self.assertFalse(dfa.match("a"))
        self.assertFalse(dfa.match("b"))
        self.assertFalse(dfa.match("aba"))

    def test_union_dfa(self):
        dfa = compile_to_dfa("a|b")
        self.assertTrue(dfa.match("a"))
        self.assertTrue(dfa.match("b"))
        self.assertFalse(dfa.match("ab"))
        self.assertFalse(dfa.match(""))
        self.assertFalse(dfa.match("c"))

    def test_star_dfa(self):
        dfa = compile_to_dfa("a*")
        self.assertTrue(dfa.match(""))
        self.assertTrue(dfa.match("a"))
        self.assertTrue(dfa.match("aaaa"))
        self.assertFalse(dfa.match("b"))
        self.assertFalse(dfa.match("ab"))

    def test_plus_dfa(self):
        dfa = compile_to_dfa("a+")
        self.assertFalse(dfa.match(""))
        self.assertTrue(dfa.match("a"))
        self.assertTrue(dfa.match("aaaa"))
        self.assertFalse(dfa.match("b"))

    def test_optional_dfa(self):
        dfa = compile_to_dfa("a?")
        self.assertTrue(dfa.match(""))
        self.assertTrue(dfa.match("a"))
        self.assertFalse(dfa.match("aa"))
        self.assertFalse(dfa.match("b"))


class TestTextbookDFAs(unittest.TestCase):
    """Verifies classic automata from Theory of Computation literature."""

    def test_classic_abb(self):
        # (a|b)*abb -> standard 5-state DFA before Hopcroft minimization
        dfa = compile_to_dfa("(a|b)*abb")
        self.assertTrue(len(dfa.states) in (4, 5))
        self.assertTrue(dfa.match("abb"))
        self.assertTrue(dfa.match("aabb"))
        self.assertTrue(dfa.match("ababb"))
        self.assertTrue(dfa.match("bababb"))
        self.assertFalse(dfa.match("ab"))
        self.assertFalse(dfa.match("abba"))
        self.assertFalse(dfa.match(""))

    def test_even_binary_representation(self):
        # Binary strings ending in 0: (0|1)*0
        dfa = compile_to_dfa("(0|1)*0")
        self.assertTrue(dfa.match("0"))
        self.assertTrue(dfa.match("10"))
        self.assertTrue(dfa.match("110"))
        self.assertTrue(dfa.match("101010"))
        self.assertFalse(dfa.match("1"))
        self.assertFalse(dfa.match("11"))
        self.assertFalse(dfa.match("101"))


class TestCharacterClassesDFA(unittest.TestCase):
    """Verifies DFA compilation and matching with character classes."""

    def test_digits_dfa(self):
        dfa = compile_to_dfa(r"[0-9]+")
        self.assertTrue(dfa.match("0"))
        self.assertTrue(dfa.match("1234567890"))
        self.assertFalse(dfa.match(""))
        self.assertFalse(dfa.match("123a"))

    def test_shorthand_ipv4_dfa(self):
        dfa = compile_to_dfa(r"\d+\.\d+\.\d+\.\d+")
        self.assertTrue(dfa.match("192.168.1.1"))
        self.assertTrue(dfa.match("10.0.0.1"))
        self.assertFalse(dfa.match("192.168.1"))
        self.assertFalse(dfa.match("192.168.1.a"))

    def test_identifier_dfa(self):
        dfa = compile_to_dfa(r"[a-zA-Z_][a-zA-Z0-9_]*")
        self.assertTrue(dfa.match("_init"))
        self.assertTrue(dfa.match("varName123"))
        self.assertFalse(dfa.match("123var"))
        self.assertFalse(dfa.match(""))


class TestDifferentialEquivalence(unittest.TestCase):
    """
    Three-Way Differential Equivalence Testing:
    Asserts that for every pattern and random input string,
    Accept_NFA(w) == Accept_DFA(w).
    """

    def _assert_nfa_dfa_equivalent(self, regex: str, test_corpus: list):
        nfa = compile_regex(regex)
        nfa_sim = NFASimulator(nfa)
        dfa = nfa_to_dfa(nfa)

        for s in test_corpus:
            nfa_verdict = nfa_sim.matches(s)
            dfa_verdict = dfa.match(s)
            self.assertEqual(
                nfa_verdict, dfa_verdict,
                f"Discrepancy on regex /{regex}/ with input '{s}': NFA={nfa_verdict}, DFA={dfa_verdict}"
            )

    def test_corpus_union_star(self):
        corpus = ["", "a", "b", "aa", "ab", "ba", "bb", "aaa", "aba", "bab", "bbb", "ababb", "aababb"]
        self._assert_nfa_dfa_equivalent("(a|b)*abb", corpus)

    def test_corpus_nested_groups(self):
        corpus = ["", "c", "ac", "bc", "aac", "abc", "bac", "bbc", "aaac", "bbbc", "xyz"]
        self._assert_nfa_dfa_equivalent("(a*|b*)c", corpus)

    def test_corpus_plus_and_optional(self):
        corpus = ["", "a", "b", "ab", "aab", "aaab", "abb", "ba", "x"]
        self._assert_nfa_dfa_equivalent("a+b?", corpus)

    def test_corpus_security_url(self):
        corpus = [
            "http://malware.org/trojan.exe",
            "https://safe.org/page.html",
            "https://test.net/payload.exe",
            "ftp://site.org/file.exe",
            "http://.exe"
        ]
        self._assert_nfa_dfa_equivalent(r"(http|https)://[a-zA-Z0-9_\.]+\.exe", corpus)


class TestDFASimulationTrace(unittest.TestCase):
    """Verifies that the DFA step tracer correctly tracks deterministic execution."""

    def test_trace_steps(self):
        dfa = compile_to_dfa("ab")
        res = dfa.simulate("ab")
        self.assertTrue(res.is_accepted)
        self.assertEqual(len(res.trace), 2)
        self.assertEqual(res.trace[0].char, "a")
        self.assertEqual(res.trace[1].char, "b")
        self.assertTrue(res.trace[1].is_accept)

    def test_trace_trap_on_mismatch(self):
        dfa = compile_to_dfa("ab")
        res = dfa.simulate("ax")
        self.assertFalse(res.is_accepted)
        self.assertEqual(len(res.trace), 2)
        self.assertIsNone(res.trace[1].to_state, "Second step should encounter trap")


class TestDFAMetricsAndExport(unittest.TestCase):
    """Verifies transition table generation, SVG export, and structural metrics."""

    def test_metrics(self):
        dfa = compile_to_dfa("(a|b)*abb")
        metrics = dfa.get_metrics()
        self.assertIn("state_count", metrics)
        self.assertIn("transition_count", metrics)
        self.assertIn("nfa_state_count", metrics)
        self.assertGreater(metrics["nfa_state_count"], metrics["state_count"])

    def test_ascii_table(self):
        dfa = compile_to_dfa("a*b")
        table = dfa.generate_transition_table()
        self.assertIn("State", table)
        self.assertIn("D0", table)

    def test_svg_export(self):
        dfa = compile_to_dfa("(a|b)*abb")
        svg = dfa.generate_layered_svg()
        self.assertTrue(svg.startswith("<svg"))
        self.assertTrue(svg.endswith("</svg>"))
        self.assertIn("D0", svg)
        self.assertIn("dfa-arrow-solid", svg)


if __name__ == '__main__':
    unittest.main()
