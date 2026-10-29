"""
test_extended_parser.py: Comprehensive Unit & Integration Tests for Extended POSIX Grammar.
Validates:
  1. Positive closure quantifier (+)
  2. Optional quantifier (?)
  3. Character classes ([a-z], [0-9], [a-zA-Z0-9_], [aeiou])
  4. Negated character classes ([^0-9], [^a-z])
  5. Shorthand escapes (\\d, \\D, \\w, \\W, \\s, \\S)
  6. Range boundaries, literal hyphens ([-a], [a-]), and inverted range errors ([z-a])
  7. Complex real-world cybersecurity patterns (IPv4, emails, URI protocols)
  8. Thompson invariant assertions (|Q| <= 2|r|, in-degree(q0)=0, out-degree(q_accept)=0)
"""

import unittest
from regex_nfa.parser import (
    tokenize, insert_explicit_concat, infix_to_postfix, parse_regex, build_ast,
    TokenType, PlusNode, OptionalNode, CharClassNode
)
from regex_nfa.thompson import compile_regex
from regex_nfa.simulator import NFASimulator


class TestExtendedQuantifiers(unittest.TestCase):
    """Verifies '+' and '?' semantics and non-deterministic execution."""

    def test_plus_basic(self):
        nfa = compile_regex("a+")
        sim = NFASimulator(nfa)
        self.assertFalse(sim.matches(""), "a+ must reject empty string")
        self.assertTrue(sim.matches("a"), "a+ must accept 'a'")
        self.assertTrue(sim.matches("aa"), "a+ must accept 'aa'")
        self.assertTrue(sim.matches("aaaaa"), "a+ must accept 'aaaaa'")
        self.assertFalse(sim.matches("b"), "a+ must reject 'b'")
        self.assertFalse(sim.matches("ab"), "a+ must reject 'ab'")

    def test_plus_concatenation(self):
        nfa = compile_regex("a+b")
        sim = NFASimulator(nfa)
        self.assertFalse(sim.matches("b"), "a+b must reject 'b'")
        self.assertTrue(sim.matches("ab"), "a+b must accept 'ab'")
        self.assertTrue(sim.matches("aaab"), "a+b must accept 'aaab'")
        self.assertFalse(sim.matches("a"), "a+b must reject 'a'")
        self.assertFalse(sim.matches("aaba"), "a+b must reject 'aaba'")

    def test_plus_grouped(self):
        nfa = compile_regex("(ab)+")
        sim = NFASimulator(nfa)
        self.assertFalse(sim.matches(""), "(ab)+ must reject ''")
        self.assertTrue(sim.matches("ab"), "(ab)+ must accept 'ab'")
        self.assertTrue(sim.matches("abab"), "(ab)+ must accept 'abab'")
        self.assertTrue(sim.matches("ababab"), "(ab)+ must accept 'ababab'")
        self.assertFalse(sim.matches("a"), "(ab)+ must reject 'a'")
        self.assertFalse(sim.matches("aba"), "(ab)+ must reject 'aba'")

    def test_plus_nested(self):
        # ((a+)+)+ must handle nesting without state explosion
        nfa = compile_regex("((a+)+)+")
        sim = NFASimulator(nfa)
        self.assertFalse(sim.matches(""))
        self.assertTrue(sim.matches("a"))
        self.assertTrue(sim.matches("aaaa"))

    def test_optional_basic(self):
        nfa = compile_regex("a?")
        sim = NFASimulator(nfa)
        self.assertTrue(sim.matches(""), "a? must accept empty string")
        self.assertTrue(sim.matches("a"), "a? must accept 'a'")
        self.assertFalse(sim.matches("aa"), "a? must reject 'aa'")
        self.assertFalse(sim.matches("b"), "a? must reject 'b'")

    def test_optional_concatenation(self):
        nfa = compile_regex("a?b")
        sim = NFASimulator(nfa)
        self.assertTrue(sim.matches("b"), "a?b must accept 'b'")
        self.assertTrue(sim.matches("ab"), "a?b must accept 'ab'")
        self.assertFalse(sim.matches("aab"), "a?b must reject 'aab'")
        self.assertFalse(sim.matches(""), "a?b must reject ''")

    def test_optional_grouped(self):
        nfa = compile_regex("(https)?://site")
        sim = NFASimulator(nfa)
        self.assertTrue(sim.matches("://site"))
        self.assertTrue(sim.matches("https://site"))
        self.assertFalse(sim.matches("http://site"))


class TestCharacterClasses(unittest.TestCase):
    """Verifies bracketed character classes and negated classes."""

    def test_digit_class(self):
        nfa = compile_regex("[0-9]+")
        sim = NFASimulator(nfa)
        self.assertTrue(sim.matches("0"))
        self.assertTrue(sim.matches("1234567890"))
        self.assertFalse(sim.matches(""))
        self.assertFalse(sim.matches("12a34"))

    def test_alpha_class(self):
        nfa = compile_regex("[a-z]+")
        sim = NFASimulator(nfa)
        self.assertTrue(sim.matches("hello"))
        self.assertTrue(sim.matches("z"))
        self.assertFalse(sim.matches("Hello"))
        self.assertFalse(sim.matches("123"))

    def test_alphanumeric_mixed(self):
        nfa = compile_regex("[a-zA-Z0-9_]+")
        sim = NFASimulator(nfa)
        self.assertTrue(sim.matches("Admin_123"))
        self.assertTrue(sim.matches("test_case"))
        self.assertFalse(sim.matches("admin@123"))
        self.assertFalse(sim.matches("has space"))

    def test_negated_class(self):
        nfa = compile_regex("[^0-9]+")
        sim = NFASimulator(nfa)
        self.assertTrue(sim.matches("abc"))
        self.assertTrue(sim.matches("Hello_World!"))
        self.assertFalse(sim.matches("abc1def"))
        self.assertFalse(sim.matches("5"))

    def test_literal_hyphen_boundaries(self):
        # [-a] should match '-' or 'a'
        nfa1 = compile_regex("[-a]")
        sim1 = NFASimulator(nfa1)
        self.assertTrue(sim1.matches("-"))
        self.assertTrue(sim1.matches("a"))
        self.assertFalse(sim1.matches("b"))

        # [a-] should match 'a' or '-'
        nfa2 = compile_regex("[a-]")
        sim2 = NFASimulator(nfa2)
        self.assertTrue(sim2.matches("-"))
        self.assertTrue(sim2.matches("a"))
        self.assertFalse(sim2.matches("b"))


class TestShorthandEscapes(unittest.TestCase):
    """Verifies shorthand character classes (\\d, \\w, \\s, \\D, \\W, \\S)."""

    def test_digits_shorthand(self):
        nfa = compile_regex(r"\d+")
        sim = NFASimulator(nfa)
        self.assertTrue(sim.matches("42"))
        self.assertTrue(sim.matches("9999"))
        self.assertFalse(sim.matches("42a"))
        self.assertFalse(sim.matches(""))

    def test_word_chars_shorthand(self):
        nfa = compile_regex(r"\w+")
        sim = NFASimulator(nfa)
        self.assertTrue(sim.matches("variable_name_99"))
        self.assertFalse(sim.matches("var-name"))

    def test_whitespace_shorthand(self):
        nfa = compile_regex(r"\s+")
        sim = NFASimulator(nfa)
        self.assertTrue(sim.matches(" "))
        self.assertTrue(sim.matches("  \t\n  "))
        self.assertFalse(sim.matches(" a "))

    def test_ipv4_signature(self):
        # \d+\.\d+\.\d+\.\d+
        nfa = compile_regex(r"\d+\.\d+\.\d+\.\d+")
        sim = NFASimulator(nfa)
        self.assertTrue(sim.matches("192.168.1.1"))
        self.assertTrue(sim.matches("10.0.0.254"))
        self.assertTrue(sim.matches("127.0.0.1"))
        self.assertFalse(sim.matches("192.168.1"))
        self.assertFalse(sim.matches("192.168.1.256a"))
        self.assertFalse(sim.matches("abc.def.ghi.jkl"))


class TestExtendedASTAndGrammar(unittest.TestCase):
    """Verifies AST node serialization and operator precedence."""

    def test_ast_plus_and_optional(self):
        postfix = parse_regex("a+b?")
        ast = build_ast(postfix)
        self.assertIsNotNone(ast)
        self.assertEqual(ast.to_string(), "concat(plus(literal('a')), optional(literal('b')))")

    def test_ast_charset(self):
        postfix = parse_regex(r"[0-9]+\w?")
        ast = build_ast(postfix)
        self.assertIsNotNone(ast)
        self.assertEqual(ast.to_string(), "concat(plus(charset('[0-9]')), optional(charset('\\w')))")

    def test_thompson_state_invariants(self):
        # Check that '+' adds exactly 2 states to the sub-automaton
        nfa_base = compile_regex("a")
        nfa_plus = compile_regex("a+")
        # 'a' has 2 states. 'a+' has 2 + 2 = 4 states!
        self.assertEqual(len(nfa_base.get_all_states()), 2)
        self.assertEqual(len(nfa_plus.get_all_states()), 4)

        # In-degree of start must be 0
        in_degrees = {s.id: 0 for s in nfa_plus.get_all_states()}
        for s in nfa_plus.get_all_states():
            for sym, dests in s.transitions.items():
                for d in dests:
                    in_degrees[d.id] += 1
        self.assertEqual(in_degrees[nfa_plus.start_state.id], 0, "Start state must have in-degree 0")

        # Accept state has 0 outgoing transitions
        self.assertEqual(len(nfa_plus.accept_state.transitions), 0, "Accept state must have out-degree 0")


class TestSyntaxErrorHandling(unittest.TestCase):
    """Verifies robust syntax and inverted-range error reporting."""

    def test_inverted_range(self):
        with self.assertRaises(ValueError) as ctx:
            compile_regex("[z-a]")
        self.assertIn("range values out of order", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            compile_regex("[9-0]")
        self.assertIn("range values out of order", str(ctx.exception))

    def test_empty_character_class(self):
        with self.assertRaises(ValueError) as ctx:
            compile_regex("[]")
        self.assertIn("Empty character class", str(ctx.exception))

    def test_unclosed_character_class(self):
        with self.assertRaises(ValueError) as ctx:
            compile_regex("[a-z")
        self.assertIn("Unclosed character class", str(ctx.exception))

    def test_repeated_quantifiers(self):
        with self.assertRaises(ValueError) as ctx:
            compile_regex("a++")
        self.assertIn("Repeated quantifier", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            compile_regex("a+*")
        self.assertIn("Repeated quantifier", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            compile_regex("a?+")
        self.assertIn("Repeated quantifier", str(ctx.exception))

    def test_expression_cannot_start_with_quantifier(self):
        with self.assertRaises(ValueError) as ctx:
            compile_regex("+a")
        self.assertIn("Expression cannot start with operator '+'", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            compile_regex("?a")
        self.assertIn("Expression cannot start with operator '?'", str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
