"""
test_engine.py: Comprehensive Theory of Computation (TOC) Automata Verification Suite.
Ported and expanded with the 80-case exhaustive test matrix from the pinnacle implementation:
- Lexer & Tokenizer
- Operator Precedence (* > · > |) & Escapes
- Thompson Invariants (Linear bounds, start=q0, accept=qF, reachability)
- ε-Closure mathematical properties & cycle safety
- Exhaustive Acceptance & Rejection Suite (45+ regular language cases)
- Multiple Concurrent NFA Paths ((a|ab)(c|bcd) branch preservation)
- Syntax Errors & Unsupported Operator Scope Protection
- Layered SVG & Transition Table Visualization
- ReDoS Algorithmic Complexity Attack Immunity
"""

import unittest
from regex_nfa.parser import (
    tokenize, insert_explicit_concat, infix_to_postfix, parse_regex,
    build_ast, format_postfix, Token, TokenType
)
from regex_nfa.thompson import compile_regex
from regex_nfa.simulator import NFASimulator
from regex_nfa.visualizer import Visualizer
from regex_nfa.nfa import SymbolKind, EPSILON, WILDCARD


class TestLexerAndParser(unittest.TestCase):
    """Tests lexical analysis, Shunting-Yard algorithm, AST, and error handling."""

    def test_basic_tokenization(self):
        tokens = tokenize("a|b*")
        types = [t.type for t in tokens]
        self.assertEqual(types, [TokenType.CHAR, TokenType.UNION, TokenType.CHAR, TokenType.STAR])

    def test_escaped_characters(self):
        tokens = tokenize(r"a\.b\/c\:d\*e\+f")
        values = [t.value for t in tokens]
        self.assertEqual(values, ["a", ".", "b", "/", "c", ":", "d", "*", "e", "+", "f"])
        self.assertTrue(all(t.escaped for t in tokens if t.value in {".", "/", ":", "*", "+"}))

    def test_escapes_produce_literal_matches(self):
        # \.exe matches .exe and rejects aexe
        nfa1 = compile_regex(r"\.exe")
        sim1 = NFASimulator(nfa1)
        self.assertTrue(sim1.matches(".exe"))
        self.assertFalse(sim1.matches("aexe"))

        # a\* matches a* and rejects aa
        nfa2 = compile_regex(r"a\*")
        sim2 = NFASimulator(nfa2)
        self.assertTrue(sim2.matches("a*"))
        self.assertFalse(sim2.matches("aa"))

    def test_wildcard_tokenization(self):
        tokens = tokenize("a.b")
        self.assertEqual(tokens[1].type, TokenType.ANY)

    def test_explicit_concatenation_rules(self):
        # 'ab' -> 'a · b'
        tokens = insert_explicit_concat(tokenize("ab"))
        self.assertEqual([t.value for t in tokens], ["a", "·", "b"])

        # '(a|b)c' -> '( a | b ) · c'
        tokens = insert_explicit_concat(tokenize("(a|b)c"))
        self.assertEqual([t.value for t in tokens], ["(", "a", "|", "b", ")", "·", "c"])

        # 'a(b|c)' -> 'a · ( b | c )'
        tokens = insert_explicit_concat(tokenize("a(b|c)"))
        self.assertEqual([t.value for t in tokens], ["a", "·", "(", "b", "|", "c", ")"])

        # 'a*b' -> 'a * · b'
        tokens = insert_explicit_concat(tokenize("a*b"))
        self.assertEqual([t.value for t in tokens], ["a", "*", "·", "b"])

        # '(ab)*' -> '( a · b ) *'
        tokens = insert_explicit_concat(tokenize("(ab)*"))
        self.assertEqual([t.value for t in tokens], ["(", "a", "·", "b", ")", "*"])

        # 'a(b|c)*' -> 'a · ( b | c ) *'
        tokens = insert_explicit_concat(tokenize("a(b|c)*"))
        self.assertEqual([t.value for t in tokens], ["a", "·", "(", "b", "|", "c", ")", "*"])

        # '(a|b)*abb' -> '( a | b ) * · a · b · b'
        tokens = insert_explicit_concat(tokenize("(a|b)*abb"))
        self.assertEqual([t.value for t in tokens], ["(", "a", "|", "b", ")", "*", "·", "a", "·", "b", "·", "b"])

    def test_operator_precedence(self):
        # Star > Concat > Union
        tokens = parse_regex("a|b*")
        self.assertEqual(format_postfix(tokens), "a b * |")

        tokens = parse_regex("ab|c")
        self.assertEqual(format_postfix(tokens), "a b · c |")

        tokens = parse_regex("a|bc")
        self.assertEqual(format_postfix(tokens), "a b c · |")

        tokens = parse_regex("ab*")
        self.assertEqual(format_postfix(tokens), "a b * ·")

        tokens = parse_regex("(ab)*")
        self.assertEqual(format_postfix(tokens), "a b · *")

        tokens = parse_regex("a(b|c)*")
        self.assertEqual(format_postfix(tokens), "a b c | * ·")

        tokens = parse_regex("(a|b)*abb")
        self.assertEqual(format_postfix(tokens), "a b | * a · b · b ·")

    def test_ast_generation(self):
        tokens = parse_regex("(a|b)*c")
        ast = build_ast(tokens)
        self.assertEqual(ast.to_string(), "concat(star(union(literal('a'), literal('b'))), literal('c'))")


class TestThompsonStructuralProperties(unittest.TestCase):
    """Verifies strict textbook invariants of Thompson's construction."""

    def test_single_literal_properties(self):
        # 'a': 2 states, 1 transition, start=q0
        nfa = compile_regex("a")
        self.assertEqual(len(nfa.get_all_states()), 2)
        trans_count = sum(len(tgts) for s in nfa.get_all_states() for tgts in s.transitions.values())
        self.assertEqual(trans_count, 1)
        self.assertEqual(nfa.start_state.id, 0)
        self.assertTrue(nfa.accept_state.is_accept)

    def test_union_properties(self):
        # 'a|b': 6 states, 6 transitions (4 ε)
        nfa = compile_regex("a|b")
        states = nfa.get_all_states()
        self.assertEqual(len(states), 6)
        eps_count = sum(len(tgts) for s in states for sym, tgts in s.transitions.items() if sym.kind == SymbolKind.EPSILON)
        self.assertEqual(eps_count, 4)
        self.assertEqual(nfa.start_state.id, 0)

    def test_star_properties(self):
        # 'a*': 4 states, 5 transitions (4 ε)
        nfa = compile_regex("a*")
        states = nfa.get_all_states()
        self.assertEqual(len(states), 4)
        eps_count = sum(len(tgts) for s in states for sym, tgts in s.transitions.items() if sym.kind == SymbolKind.EPSILON)
        self.assertEqual(eps_count, 4)
        self.assertEqual(nfa.start_state.id, 0)

    def test_accept_state_has_no_outgoing_transitions(self):
        # Accept state in final NFA must be terminal
        for p in ["a", "ab", "a|b", "a*", "a*b", "(a|b)*abb", r"(http|https)://.*\.exe"]:
            nfa = compile_regex(p)
            self.assertEqual(len(nfa.accept_state.transitions), 0)

    def test_every_state_is_reachable_and_renumbered(self):
        for p in ["a", "ab", "a|b", "a*", "a*b", "(a|b)*abb", "a(b|c)*d"]:
            nfa = compile_regex(p)
            states = nfa.get_all_states()
            ids = sorted([s.id for s in states])
            self.assertEqual(ids, list(range(len(states))))
            self.assertEqual(nfa.start_state.id, 0)


class TestEpsilonClosure(unittest.TestCase):
    """Validates mathematical correctness of ε-closure E(S)."""

    def test_closure_of_start_in_star_includes_accept(self):
        nfa = compile_regex("a*")
        sim = NFASimulator(nfa)
        init_closure = sim.epsilon_closure({nfa.start_state})
        self.assertIn(nfa.accept_state, init_closure)

    def test_closure_of_literal_start_is_itself(self):
        nfa = compile_regex("a")
        sim = NFASimulator(nfa)
        init_closure = sim.epsilon_closure({nfa.start_state})
        self.assertEqual(init_closure, {nfa.start_state})

    def test_closure_terminates_on_cycles(self):
        nfa = compile_regex("(a|b)*")
        sim = NFASimulator(nfa)
        # Must terminate in finite time without RecursionError
        closure = sim.epsilon_closure({nfa.start_state})
        self.assertGreater(len(closure), 1)


class TestLanguageAcceptanceExhaustive(unittest.TestCase):
    """Exhaustive regular language acceptance and rejection matrix (45+ cases)."""

    def check_matches(self, pattern: str, string: str, expected: bool):
        nfa = compile_regex(pattern)
        sim = NFASimulator(nfa)
        self.assertEqual(sim.matches(string), expected, f"Pattern /{pattern}/ on '{string}' expected {expected}")

    # Single literal 'a'
    def test_single_literal_accept(self): self.check_matches("a", "a", True)
    def test_single_literal_reject_mismatch(self): self.check_matches("a", "b", False)
    def test_single_literal_reject_empty(self): self.check_matches("a", "", False)
    def test_single_literal_reject_repeated(self): self.check_matches("a", "aa", False)

    # Concatenation 'ab'
    def test_concat_ab_accept(self): self.check_matches("ab", "ab", True)
    def test_concat_ab_reject_prefix(self): self.check_matches("ab", "a", False)
    def test_concat_ab_reject_extended(self): self.check_matches("ab", "abb", False)
    def test_concat_abc_accept(self): self.check_matches("abc", "abc", True)

    # Union 'a|b'
    def test_union_accept_a(self): self.check_matches("a|b", "a", True)
    def test_union_accept_b(self): self.check_matches("a|b", "b", True)
    def test_union_reject_c(self): self.check_matches("a|b", "c", False)
    def test_union_reject_ab(self): self.check_matches("a|b", "ab", False)
    def test_union_compound_accept(self): self.check_matches("a|bc", "bc", True)
    def test_union_compound_reject(self): self.check_matches("a|bc", "ac", False)

    # Kleene star 'a*'
    def test_star_accept_empty(self): self.check_matches("a*", "", True)
    def test_star_accept_single(self): self.check_matches("a*", "a", True)
    def test_star_accept_multiple(self): self.check_matches("a*", "aaaa", True)
    def test_star_reject_other(self): self.check_matches("a*", "b", False)

    # Star concat 'a*b'
    def test_star_concat_accept_zero(self): self.check_matches("a*b", "b", True)
    def test_star_concat_accept_one(self): self.check_matches("a*b", "ab", True)
    def test_star_concat_accept_many(self): self.check_matches("a*b", "aaab", True)
    def test_star_concat_reject_no_b(self): self.check_matches("a*b", "a", False)
    def test_star_concat_reject_wrong_order(self): self.check_matches("a*b", "ba", False)
    def test_star_concat_reject_trailing(self): self.check_matches("a*b", "aaba", False)

    # Concat star 'ab*'
    def test_concat_star_accept(self): self.check_matches("ab*", "abbb", True)
    def test_concat_star_accept_empty_star(self): self.check_matches("ab*", "a", True)
    def test_concat_star_reject(self): self.check_matches("ab*", "ba", False)

    # Group star '(ab)*'
    def test_group_star_accept_empty(self): self.check_matches("(ab)*", "", True)
    def test_group_star_accept_repeat(self): self.check_matches("(ab)*", "abab", True)
    def test_group_star_reject_partial(self): self.check_matches("(ab)*", "aba", False)

    # Union star '(a|b)*'
    def test_union_star_accept_mixed(self): self.check_matches("(a|b)*", "abbaab", True)
    def test_union_star_reject_alien(self): self.check_matches("(a|b)*", "abc", False)
    def test_union_star_accept_empty(self): self.check_matches("(a|b)*", "", True)

    # Textbook expression '(a|b)*abb'
    def test_textbook_accept_minimal(self): self.check_matches("(a|b)*abb", "abb", True)
    def test_textbook_accept_long(self): self.check_matches("(a|b)*abb", "aabb", True)
    def test_textbook_accept_alternating(self): self.check_matches("(a|b)*abb", "abababb", True)
    def test_textbook_reject_short(self): self.check_matches("(a|b)*abb", "ab", False)
    def test_textbook_reject_wrong_char(self): self.check_matches("(a|b)*abb", "abc", False)
    def test_textbook_reject_wrong_suffix(self): self.check_matches("(a|b)*abb", "abba", False)

    # Nested patterns 'a(b|c)*' and '((a|b)c)*'
    def test_nested_accept_base(self): self.check_matches("a(b|c)*", "a", True)
    def test_nested_accept_sequence(self): self.check_matches("a(b|c)*", "abcbc", True)
    def test_nested_reject(self): self.check_matches("a(b|c)*", "abd", False)
    def test_deeply_nested_accept(self): self.check_matches("((a|b)c)*", "acbc", True)
    def test_deeply_nested_reject(self): self.check_matches("((a|b)c)*", "acb", False)

    # Wildcards & Escapes
    def test_wildcard_dot_accept(self): self.check_matches("a.b", "axb", True)
    def test_wildcard_dot_accept_digit(self): self.check_matches("a.b", "a1b", True)
    def test_wildcard_dot_reject(self): self.check_matches("a.b", "ab", False)
    def test_escaped_dot_accept(self): self.check_matches(r"a\.b", "a.b", True)
    def test_escaped_dot_reject(self): self.check_matches(r"a\.b", "axb", False)
    def test_matches_convenience_function(self):
        nfa = compile_regex(r"(http|https)://.*\.exe")
        sim = NFASimulator(nfa)
        self.assertTrue(sim.matches("https://site.com/malware.exe"))
        self.assertFalse(sim.matches("https://site.com/index.html"))


class TestMultipleNfaPaths(unittest.TestCase):
    """Verifies that non-deterministic exploration maintains multiple parallel active states."""

    def test_multiple_paths_both_branches_alive(self):
        # (a|ab)(c|bcd) accepts 'abcd':
        # Branch 1 consumes 'a', needs 'bcd'.
        # Branch 2 consumes 'ab', needs 'cd' (fails).
        # Engine must keep branch 1 alive to accept!
        nfa = compile_regex("(a|ab)(c|bcd)")
        sim = NFASimulator(nfa)
        self.assertTrue(sim.matches("abcd"))

    def test_trace_tracks_multiple_active_states(self):
        nfa = compile_regex("(a|b)*abb")
        sim = NFASimulator(nfa)
        res = sim.simulate("ababb")
        self.assertTrue(res.is_accepted)
        # Verify that during simulation, active states set size > 1
        max_active = max(len(step.after_states) for step in res.trace)
        self.assertGreater(max_active, 1)

    def test_dead_configuration_reported(self):
        nfa = compile_regex("ab")
        sim = NFASimulator(nfa)
        res = sim.simulate("ax")
        self.assertFalse(res.is_accepted)
        self.assertEqual(len(res.final_states), 0)


class TestInvalidAndUnsupportedRegexes(unittest.TestCase):
    """Verifies robust syntax validation and scope boundary protection."""

    def test_syntax_errors(self):
        bad_patterns = [
            "(a|b",     # unmatched '('
            "a|b)",     # unmatched ')'
            "|ab",      # leading '|'
            "ab|",      # trailing '|'
            "a||b",     # double '|'
            "a**",      # double '*'
            "*a",       # leading '*'
            "(*a)",     # leading '*' in group
            "()",       # empty group
            "",         # empty string
            r"ab\\"[0:-1] # trailing backslash
        ]
        for p in bad_patterns:
            with self.assertRaises(Exception, msg=f"Pattern '{p}' should raise error"):
                compile_regex(p)

    def test_unsupported_operators_and_quantifier_syntax(self):
        # Invalid quantifier syntax or orphaned operators must be rejected with descriptive errors
        invalid = [
            ("{5}", "no preceding operand"),
            ("a{5,2}", "must satisfy"),
            ("a{", "unclosed quantifier"),
            ("a}", "unmatched closing brace"),
            ("a{abc}", "invalid quantifier"),
            ("a{100}", "out of range"),
        ]
        for p, token_desc in invalid:
            with self.assertRaises(Exception, msg=f"Pattern '{p}' ({token_desc}) should raise error"):
                compile_regex(p)

    def test_bounded_quantifiers_and_anchors(self):
        # Verify bounded quantifiers {n}, {n,m}, {n,}, anchors, and hex escapes
        nfa_exact = compile_regex("a{3}")
        sim_exact = NFASimulator(nfa_exact)
        self.assertTrue(sim_exact.simulate("aaa").is_accepted)
        self.assertFalse(sim_exact.simulate("aa").is_accepted)
        self.assertFalse(sim_exact.simulate("aaaa").is_accepted)

        nfa_range = compile_regex("a{2,4}b")
        sim_range = NFASimulator(nfa_range)
        self.assertTrue(sim_range.simulate("aab").is_accepted)
        self.assertTrue(sim_range.simulate("aaab").is_accepted)
        self.assertTrue(sim_range.simulate("aaaab").is_accepted)
        self.assertFalse(sim_range.simulate("ab").is_accepted)
        self.assertFalse(sim_range.simulate("aaaaab").is_accepted)

        nfa_atleast = compile_regex("a{2,}")
        sim_atleast = NFASimulator(nfa_atleast)
        self.assertTrue(sim_atleast.simulate("aa").is_accepted)
        self.assertTrue(sim_atleast.simulate("aaaaa").is_accepted)
        self.assertFalse(sim_atleast.simulate("a").is_accepted)

        nfa_anchored = compile_regex("^abc$")
        sim_anchored = NFASimulator(nfa_anchored)
        self.assertTrue(sim_anchored.simulate("abc").is_accepted)
        self.assertFalse(sim_anchored.simulate("abcd").is_accepted)

        nfa_hex = compile_regex(r"[\x30-\x39]+")
        sim_hex = NFASimulator(nfa_hex)
        self.assertTrue(sim_hex.simulate("12345").is_accepted)
        self.assertFalse(sim_hex.simulate("abc").is_accepted)


class TestReDoSImmunity(unittest.TestCase):
    """Proves Thompson's NFA simulation is immune to catastrophic backtracking (ReDoS)."""

    def test_pathological_re_execution_time(self):
        # In backtracking engines (Python 're'), (a*)*b on 'aaaa...a' takes O(2^n) time and hangs.
        # Thompson simulation must execute in sub-millisecond linear time!
        nfa = compile_regex("(a*)*b")
        sim = NFASimulator(nfa)
        res = sim.simulate("a" * 50)
        self.assertFalse(res.is_accepted)
        self.assertLess(res.elapsed_ms, 50.0, "Thompson simulation should execute in < 50ms on pathological input")


class TestVisualization(unittest.TestCase):
    """Verifies state transition tables and layered SVG generation."""

    def test_transition_table_generation(self):
        nfa = compile_regex("a*b")
        table_str = Visualizer.generate_transition_table(nfa)
        self.assertIn("->  q0", table_str)
        self.assertIn("*  q", table_str)

    def test_layered_svg_generation(self):
        nfa = compile_regex("(a|b)*abb")
        svg = Visualizer.generate_layered_svg(nfa)
        self.assertTrue(svg.startswith("<svg"))
        self.assertTrue(svg.endswith("</svg>"))
        self.assertIn("q0", svg)
        self.assertIn("q13", svg)
        self.assertIn("arrow-solid", svg)
        self.assertIn("arrow-eps", svg)


if __name__ == '__main__':
    unittest.main()
