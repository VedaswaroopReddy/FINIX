"""
test_unanchored_and_bytes.py: Formal Unit Tests for Native Unanchored Substring Search,
DFA Substring Extraction (search / find_all), and 256-Stride Byte Stream Traversal.
"""

import pytest
from regex_nfa.thompson import compile_regex
from regex_nfa.dfa import compile_to_dfa, DFA, ALPHABET_LIMIT, ASCII_LIMIT
from regex_nfa.minimizer import compile_to_minimal_dfa
from regex_nfa.nfa import make_unanchored_nfa


class TestUnanchoredCompilation:
    """Verifies Σ* · L(r) · Σ* native unanchored compilation."""

    def test_unanchored_literal(self):
        """Pattern 'admin' unanchored matches anywhere in input string."""
        anchored_dfa = compile_to_minimal_dfa("admin", anchored=True)
        unanchored_dfa = compile_to_minimal_dfa("admin", anchored=False)

        # Anchored requires exact match
        assert anchored_dfa.match("admin") is True
        assert anchored_dfa.match("GET /admin/dashboard HTTP/1.1") is False
        assert anchored_dfa.match("superadmin") is False

        # Unanchored matches as a substring anywhere
        assert unanchored_dfa.match("admin") is True
        assert unanchored_dfa.match("GET /admin/dashboard HTTP/1.1") is True
        assert unanchored_dfa.match("superadmin") is True
        assert unanchored_dfa.match("admin_portal") is True
        assert unanchored_dfa.match("guest_user") is False

    def test_unanchored_complex_pattern(self):
        """Pattern '\\d+\\.\\d+' matches floating point numbers embedded in text."""
        dfa = compile_to_minimal_dfa(r"\d+\.\d+", anchored=False)

        assert dfa.match("The CPU load is 3.14% currently.") is True
        assert dfa.match("Sensor reading: 0.05") is True
        assert dfa.match("No float here: 12345") is False
        assert dfa.match("Text only") is False

    def test_make_unanchored_nfa_immutability(self):
        """make_unanchored_nfa must not corrupt or mutate the original NFA."""
        orig_nfa = compile_regex("abc")
        orig_states_count = len(orig_nfa.get_all_states())

        unanchored_nfa = make_unanchored_nfa(orig_nfa)
        # Original NFA states remain unchanged
        assert len(orig_nfa.get_all_states()) == orig_states_count
        assert orig_nfa.accept_state.is_accept is True

        # Unanchored NFA has expanded state space
        assert len(unanchored_nfa.get_all_states()) > orig_states_count


class TestDFASubstringSearch:
    """Verifies DFA.search() and DFA.find_all() substring extraction."""

    def test_search_first_match(self):
        dfa = compile_to_minimal_dfa(r"\d+\.\d+")
        text = "Voltage is 12.5V and current is 2.4A."
        span = dfa.search(text)
        assert span is not None
        start, end = span
        assert text[start:end] == "12.5"

    def test_search_no_match(self):
        dfa = compile_to_minimal_dfa(r"\d+")
        text = "no digits inside this sentence"
        assert dfa.search(text) is None

    def test_find_all_token_extraction(self):
        dfa = compile_to_minimal_dfa(r"\d+")
        text = "Host 192.168.1.100 port 8080"
        matches = dfa.find_all(text)

        assert len(matches) == 5
        assert [m[2] for m in matches] == ["192", "168", "1", "100", "8080"]
        # Verify indices
        for start, end, s in matches:
            assert text[start:end] == s

    def test_find_all_word_tokens(self):
        dfa = compile_to_minimal_dfa(r"[a-zA-Z_][a-zA-Z0-9_]*")
        code = "def parse_tokens(x1, y2):"
        matches = dfa.find_all(code)
        tokens = [m[2] for m in matches]
        assert tokens == ["def", "parse_tokens", "x1", "y2"]


class TestExtendedAlphabetAndByteStream:
    """Verifies 256-stride byte stream architecture (0..255)."""

    def test_alphabet_limit_constants(self):
        assert ALPHABET_LIMIT == 256
        assert ASCII_LIMIT == 256

    def test_jump_table_stride(self):
        dfa = compile_to_minimal_dfa("a*b")
        assert len(dfa.fast_table[0]) == 256

    def test_wildcard_accepts_extended_bytes(self):
        """Wildcard . must accept non-ASCII bytes (128..255)."""
        dfa = compile_to_minimal_dfa("a.b")
        # chr(169) is © (copyright), chr(233) is é, chr(255) is ÿ
        assert dfa.match(f"a{chr(169)}b") is True
        assert dfa.match(f"a{chr(233)}b") is True
        assert dfa.match(f"a{chr(255)}b") is True
        assert dfa.match("acb") is True
        assert dfa.match("ab") is False

    def test_high_byte_literal(self):
        """Matches specific byte values in 128..255 range."""
        high_char = chr(200)
        dfa = compile_to_minimal_dfa(f"prefix{high_char}suffix")
        assert dfa.match(f"prefix{high_char}suffix") is True
        assert dfa.match("prefixAsuffix") is False
