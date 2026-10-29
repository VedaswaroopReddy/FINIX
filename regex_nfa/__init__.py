"""
FINIX (RegexNFA): A Formally Verified, Linear-Time Regular Expression Engine
Built from First Principles for High-Throughput Security Pattern Matching and ReDoS Mitigation.

Complete 3-Tier Architecture:
  - Phase 1: Inductive Thompson ε-NFA & Parallel State-Set Simulator.
  - Phase 2: Rabin-Scott Powerset DFA & 2D Contiguous Jump-Table Matcher.
  - Phase 3: Hopcroft O(|Σ| n log n) Minimal DFA & SIEM Log Stream Engine.
"""

from .parser import parse_regex, insert_explicit_concat, infix_to_postfix
from .nfa import State, NFA, EPSILON, WILDCARD, make_unanchored_nfa
from .thompson import compile_regex
from .simulator import NFASimulator
from .security import SecurityScanner, SecurityRule
from .dfa import DFA, DFAState, nfa_to_dfa, compile_to_dfa
from .minimizer import (
    HopcroftMinimizer,
    minimize_dfa,
    compile_to_minimal_dfa,
    are_isomorphic,
    are_equivalent_regexes,
    prove_regex_equivalence,
)
from .benchmarks import ReDoSBenchmarkSuite, BENCHMARK_TAXONOMIES
from .scanner import SIEMRule, MasterSecurityDFA, SIEMLogScanner

__all__ = [
    "parse_regex",
    "insert_explicit_concat",
    "infix_to_postfix",
    "State",
    "NFA",
    "EPSILON",
    "WILDCARD",
    "compile_regex",
    "make_unanchored_nfa",
    "NFASimulator",
    "SecurityScanner",
    "SecurityRule",
    "DFA",
    "DFAState",
    "nfa_to_dfa",
    "compile_to_dfa",
    "HopcroftMinimizer",
    "minimize_dfa",
    "compile_to_minimal_dfa",
    "are_isomorphic",
    "are_equivalent_regexes",
    "prove_regex_equivalence",
    "ReDoSBenchmarkSuite",
    "BENCHMARK_TAXONOMIES",
    "SIEMRule",
    "MasterSecurityDFA",
    "SIEMLogScanner",
]
