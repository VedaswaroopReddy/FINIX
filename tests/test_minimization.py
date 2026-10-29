"""
tests/test_minimization.py: Unit and Formal Verification Tests for Hopcroft's DFA Minimizer.

Verifies:
  1. Textbook DFA minimization results (e.g. (a|b)*abb -> 4 states).
  2. Redundant branch collapsing and dead-end elimination.
  3. Formal language equivalence theorem prover: are_equivalent_regexes(r1, r2).
  4. Isomorphism of canonical minimal DFAs for algebraic equivalents.
  5. Simulation and matching parity: L(NFA) == L(Powerset DFA) == L(Minimal DFA).
"""

import pytest
from regex_nfa import (
    compile_regex,
    compile_to_dfa,
    compile_to_minimal_dfa,
    minimize_dfa,
    are_isomorphic,
    are_equivalent_regexes,
    prove_regex_equivalence,
)
from regex_nfa.simulator import NFASimulator


class TestTextbookMinimization:
    """Verifies standard theoretical examples from Hopcroft, Motwani & Ullman (2001)."""

    def test_classic_abb_is_already_minimal(self):
        """Pattern (a|b)*abb has exactly 4 states in its minimal DFA."""
        regex = "(a|b)*abb"
        min_dfa = compile_to_minimal_dfa(regex)

        assert len(min_dfa.states) == 4, f"Expected 4 states, got {len(min_dfa.states)}"
        # Verify language acceptance
        assert min_dfa.match("abb") is True
        assert min_dfa.match("aabb") is True
        assert min_dfa.match("babb") is True
        assert min_dfa.match("ababb") is True
        assert min_dfa.match("bbbbabb") is True

        assert min_dfa.match("") is False
        assert min_dfa.match("ab") is False
        assert min_dfa.match("abba") is False
        assert min_dfa.match("abbb") is False

    def test_even_binary_representation(self):
        """Pattern (0|1)*0 ends with '0', exactly 2 states in minimal DFA."""
        regex = "(0|1)*0"
        min_dfa = compile_to_minimal_dfa(regex)

        assert len(min_dfa.states) == 2, f"Expected 2 states, got {len(min_dfa.states)}"
        assert min_dfa.match("0") is True
        assert min_dfa.match("10") is True
        assert min_dfa.match("110") is True
        assert min_dfa.match("010") is True

        assert min_dfa.match("") is False
        assert min_dfa.match("1") is False
        assert min_dfa.match("101") is False


class TestRedundantBranchCollapsing:
    """Verifies that redundant states and duplicate paths collapse into canonical forms."""

    def test_redundant_or_branches(self):
        """Pattern a(b|b) should collapse to 3 states: D0 -(a)-> D1 -(b)-> D2 (accept)."""
        min_dfa = compile_to_minimal_dfa("a(b|b)")
        assert len(min_dfa.states) == 3
        assert min_dfa.match("ab") is True
        assert min_dfa.match("a") is False
        assert min_dfa.match("abb") is False

    def test_star_of_star_collapse(self):
        """Pattern (a*)* collapses to single 1-state universal loop."""
        min_dfa = compile_to_minimal_dfa("(a*)*")
        assert len(min_dfa.states) == 1
        assert min_dfa.states[0].is_accept is True
        assert min_dfa.match("") is True
        assert min_dfa.match("a") is True
        assert min_dfa.match("aaaaa") is True
        assert min_dfa.match("b") is False

    def test_concatenation_of_stars(self):
        """Pattern a*a* is equivalent to a* -> 1 state."""
        min_dfa = compile_to_minimal_dfa("a*a*")
        assert len(min_dfa.states) == 1
        assert min_dfa.states[0].is_accept is True
        assert min_dfa.match("") is True
        assert min_dfa.match("aaaa") is True

    def test_distributive_law_merging(self):
        """a(b|c) and ab|ac both reduce to identical 3-state minimal DFAs."""
        dfa1 = compile_to_minimal_dfa("a(b|c)")
        dfa2 = compile_to_minimal_dfa("ab|ac")

        assert len(dfa1.states) == 3
        assert len(dfa2.states) == 3
        assert are_isomorphic(dfa1, dfa2) is True


class TestLanguageEquivalenceTheoremProver:
    """Verifies the automated equivalence checker across algebraic regular identities."""

    def test_plus_equivalence(self):
        """a+ is equivalent to aa*."""
        is_eq, msg = are_equivalent_regexes("a+", "aa*")
        assert is_eq is True, msg

    def test_kleene_star_composition(self):
        """(a|b)* is equivalent to (a*b*)*."""
        is_eq, msg = are_equivalent_regexes("(a|b)*", "(a*b*)*")
        assert is_eq is True, msg

    def test_sliding_kleene_star(self):
        """(ab)*a is equivalent to a(ba)*."""
        is_eq, msg = are_equivalent_regexes("(ab)*a", "a(ba)*")
        assert is_eq is True, msg

    def test_non_equivalent_regexes(self):
        """a*b* is NOT equivalent to (a|b)*."""
        is_eq, msg = are_equivalent_regexes("a*b*", "(a|b)*")
        assert is_eq is False, msg
        assert "NOT EQUIVALENT" in msg

    def test_non_equivalent_strict_subset(self):
        """a+ is NOT equivalent to a* (empty string difference)."""
        is_eq, msg = are_equivalent_regexes("a+", "a*")
        assert is_eq is False, msg
        assert "NOT EQUIVALENT" in msg

    def test_witness_synthesis_empty_string_difference(self):
        """a* contains empty string ε which a+ does not; witness must be empty string."""
        res = prove_regex_equivalence("a+", "a*")
        assert res["is_equivalent"] is False
        assert res["is_subset_l1_of_l2"] is True
        assert res["witness_l1_minus_l2"] is None
        assert res["witness_l2_minus_l1"] == ""  # epsilon

    def test_witness_synthesis_disjoint_counterexamples(self):
        """(a|b)*abb and (a|b)*ab are disjoint; witnesses must be 'abb' and 'ab'."""
        res = prove_regex_equivalence("(a|b)*abb", "(a|b)*ab")
        assert res["is_equivalent"] is False
        assert res["witness_l1_minus_l2"] == "abb"
        assert res["witness_l2_minus_l1"] == "ab"

    def test_witness_synthesis_equivalent_identities(self):
        """Equivalent regexes have zero counterexamples."""
        res = prove_regex_equivalence("a+", "aa*")
        assert res["is_equivalent"] is True
        assert res["witness_l1_minus_l2"] is None
        assert res["witness_l2_minus_l1"] is None


class TestCharacterClassMinimization:
    """Verifies Hopcroft minimization over character classes and shorthands."""

    def test_digits_plus_minimal(self):
        """\\d+ requires exactly 2 states: D0 -(0-9)-> D1* -(0-9)-> D1*."""
        min_dfa = compile_to_minimal_dfa(r"\d+")
        assert len(min_dfa.states) == 2
        assert min_dfa.states[0].is_accept is False
        assert min_dfa.states[1].is_accept is True

        assert min_dfa.match("12345") is True
        assert min_dfa.match("0") is True
        assert min_dfa.match("") is False
        assert min_dfa.match("12a34") is False

    def test_word_tokens_minimal(self):
        """[a-z]+ requires exactly 2 states."""
        min_dfa = compile_to_minimal_dfa("[a-z]+")
        assert len(min_dfa.states) == 2
        assert min_dfa.match("hello") is True
        assert min_dfa.match("123") is False


class TestThreeTierParity:
    """Exhaustively verifies L(NFA) == L(Powerset DFA) == L(Minimal DFA)."""

    @pytest.mark.parametrize("pattern,corpus", [
        (
            "(a|b)*abb",
            ["abb", "aabb", "babb", "ababb", "", "a", "b", "ab", "abba", "abbb"]
        ),
        (
            "a(b|c)+d",
            ["abd", "acd", "abbd", "abcd", "acbd", "", "a", "ad", "abe", "ab"]
        ),
        (
            r"\d+\.\d+",
            ["3.14", "0.0", "123.456", "1.", ".1", "abc", "123", ""]
        ),
        (
            "admin|login|root",
            ["admin", "login", "root", "admi", "log", "guest", ""]
        )
    ])
    def test_full_engine_parity(self, pattern, corpus):
        nfa = compile_regex(pattern)
        powerset_dfa = compile_to_dfa(pattern)
        min_dfa = compile_to_minimal_dfa(pattern)

        for text in corpus:
            nfa_verdict = NFASimulator(nfa).matches(text)
            power_verdict = powerset_dfa.match(text)
            min_verdict = min_dfa.match(text)

            assert nfa_verdict == power_verdict == min_verdict, (
                f"Mismatch for pattern '{pattern}' on input '{text}': "
                f"NFA={nfa_verdict}, PowersetDFA={power_verdict}, MinDFA={min_verdict}"
            )


class TestMinDFAVisualAndMetricProperties:
    """Verifies metric export and state reduction ratio for minimal DFAs."""

    def test_reduction_metrics(self):
        regex = "a(b|c)d|a(b|c)e"
        powerset_dfa = compile_to_dfa(regex)
        min_dfa = powerset_dfa.minimize()

        # Minimal DFA must have fewer or equal states compared to powerset DFA
        assert len(min_dfa.states) <= len(powerset_dfa.states)
        metrics = min_dfa.get_metrics()
        assert "state_count" in metrics
        assert "transition_count" in metrics

    def test_ascii_table_and_dict_serialization(self):
        min_dfa = compile_to_minimal_dfa("a(b|c)")
        ascii_table = min_dfa.generate_transition_table()
        assert "State" in ascii_table
        assert "D0" in ascii_table

        d = min_dfa.to_dict()
        assert "metrics" in d
        assert "nodes" in d
        assert "edges" in d
        assert "table" in d
