"""
thompson.py: Inductive Thompson's Construction Algorithm.
Synthesizes an ε-NFA from Postfix Tokens / AST with strict invariant guarantees:
  1. Exactly 1 start state and 1 accept state per fragment
  2. Accept state has zero outgoing edges within fragment
  3. Linear state bounds: |Q| <= 2 * |regex|
"""

from typing import List
from .nfa import State, NFA, Symbol
from .parser import Token, TokenType, parse_regex


def build_literal_nfa(char: str) -> NFA:
    """Base Case: (s0) --char--> ((s1))"""
    s0 = State()
    s1 = State(is_accept=True)
    s0.add_transition(Symbol.char(char), s1)
    return NFA(s0, s1)


def build_wildcard_nfa() -> NFA:
    """Base Case (Wildcard): (s0) --Σ--> ((s1))"""
    s0 = State()
    s1 = State(is_accept=True)
    s0.add_transition(Symbol.any(), s1)
    return NFA(s0, s1)


def build_concat_nfa(nfa1: NFA, nfa2: NFA) -> NFA:
    """
    Concatenation (nfa1 · nfa2):
      (nfa1.start) ... (nfa1.accept) --ε--> (nfa2.start) ... ((nfa2.accept))
    """
    nfa1.accept_state.is_accept = False
    nfa1.accept_state.add_transition(Symbol.epsilon(), nfa2.start_state)
    return NFA(nfa1.start_state, nfa2.accept_state)


def build_union_nfa(nfa1: NFA, nfa2: NFA) -> NFA:
    """
    Union (nfa1 | nfa2):
                ┌-- ε --> (nfa1.start) ... (nfa1.accept) -- ε --┐
      (start) --┤                                               ├--> ((accept))
                └-- ε --> (nfa2.start) ... (nfa2.accept) -- ε --┘
    """
    start = State()
    accept = State(is_accept=True)

    nfa1.accept_state.is_accept = False
    nfa2.accept_state.is_accept = False

    start.add_transition(Symbol.epsilon(), nfa1.start_state)
    start.add_transition(Symbol.epsilon(), nfa2.start_state)

    nfa1.accept_state.add_transition(Symbol.epsilon(), accept)
    nfa2.accept_state.add_transition(Symbol.epsilon(), accept)

    return NFA(start, accept)


def build_star_nfa(nfa_inner: NFA) -> NFA:
    """
    Kleene Star (nfa*):
                ┌----------------- ε -----------------┐
                ↓                                     │
      (start) --+-- ε --> (inner.start) ... (inner.accept) -- ε --> ((accept))
         │                                                            ↑
         └---------------------------- ε -----------------------------┘
    """
    start = State()
    accept = State(is_accept=True)

    nfa_inner.accept_state.is_accept = False

    # 1. Zero occurrences bypass: start -> accept
    start.add_transition(Symbol.epsilon(), accept)

    # 2. Enter inner sub-automaton: start -> inner.start
    start.add_transition(Symbol.epsilon(), nfa_inner.start_state)

    # 3. Loop back for repetitions: inner.accept -> inner.start
    nfa_inner.accept_state.add_transition(Symbol.epsilon(), nfa_inner.start_state)

    # 4. Exit to new accept state: inner.accept -> accept
    nfa_inner.accept_state.add_transition(Symbol.epsilon(), accept)

    return NFA(start, accept)


def build_charset_nfa(charset_vals: frozenset, display_str: str) -> NFA:
    """Base Case (Character Class): (s0) --[charset]--> ((s1))"""
    s0 = State()
    s1 = State(is_accept=True)
    s0.add_transition(Symbol.charset(charset_vals, display_str), s1)
    return NFA(s0, s1)


def build_plus_nfa(nfa_inner: NFA) -> NFA:
    """
    Positive Closure (nfa+): 1 or more occurrences.
    Direct Thompson gadget: exactly 2 new states, 0 AST duplication.
                ┌----------------- ε -----------------┐
                ↓                                     │
      (start) --+-- ε --> (inner.start) ... (inner.accept) -- ε --> ((accept))
    """
    start = State()
    accept = State(is_accept=True)

    nfa_inner.accept_state.is_accept = False

    # 1. Enter inner: start -> inner.start (must match at least once!)
    start.add_transition(Symbol.epsilon(), nfa_inner.start_state)

    # 2. Loop back for repetitions: inner.accept -> inner.start
    nfa_inner.accept_state.add_transition(Symbol.epsilon(), nfa_inner.start_state)

    # 3. Exit to accept: inner.accept -> accept
    nfa_inner.accept_state.add_transition(Symbol.epsilon(), accept)

    return NFA(start, accept)


def build_optional_nfa(nfa_inner: NFA) -> NFA:
    """
    Optional Quantifier (nfa?): 0 or 1 occurrence.
    Direct Thompson gadget: exactly 2 new states, 0 AST duplication.
          ┌---------------------------- ε -----------------------------┐
          │                                                            ↓
       (start) -- ε --> (inner.start) ... (inner.accept) -- ε --> ((accept))
    """
    start = State()
    accept = State(is_accept=True)

    nfa_inner.accept_state.is_accept = False

    # 1. Zero occurrences bypass: start -> accept
    start.add_transition(Symbol.epsilon(), accept)

    # 2. One occurrence: start -> inner.start
    start.add_transition(Symbol.epsilon(), nfa_inner.start_state)

    # 3. Exit from inner: inner.accept -> accept
    nfa_inner.accept_state.add_transition(Symbol.epsilon(), accept)

    return NFA(start, accept)


def thompson_construction(postfix_tokens: List[Token]) -> NFA:
    """
    Executes Thompson's Construction using an evaluation stack on postfix tokens.
    """
    State.reset_counter(0)
    stack: List[NFA] = []

    for token in postfix_tokens:
        if token.type == TokenType.CHAR:
            stack.append(build_literal_nfa(token.value))
        elif token.type == TokenType.ANY:
            stack.append(build_wildcard_nfa())
        elif token.type == TokenType.CHAR_CLASS:
            stack.append(build_charset_nfa(token.charset or frozenset(), token.value))
        elif token.type == TokenType.CONCAT:
            if len(stack) < 2:
                raise ValueError("Thompson Construction Error: Insufficient operands for Concatenation")
            n2 = stack.pop()
            n1 = stack.pop()
            stack.append(build_concat_nfa(n1, n2))
        elif token.type == TokenType.UNION:
            if len(stack) < 2:
                raise ValueError("Thompson Construction Error: Insufficient operands for Union")
            n2 = stack.pop()
            n1 = stack.pop()
            stack.append(build_union_nfa(n1, n2))
        elif token.type == TokenType.STAR:
            if len(stack) < 1:
                raise ValueError("Thompson Construction Error: Insufficient operands for Kleene Star (*)")
            n = stack.pop()
            stack.append(build_star_nfa(n))
        elif token.type == TokenType.PLUS:
            if len(stack) < 1:
                raise ValueError("Thompson Construction Error: Insufficient operands for Positive Closure (+)")
            n = stack.pop()
            stack.append(build_plus_nfa(n))
        elif token.type == TokenType.OPTIONAL:
            if len(stack) < 1:
                raise ValueError("Thompson Construction Error: Insufficient operands for Optional (?)")
            n = stack.pop()
            stack.append(build_optional_nfa(n))
        else:
            raise ValueError(f"Unexpected token in Thompson Construction: {token}")

    if len(stack) != 1:
        raise ValueError(f"Malformed regular expression: {len(stack)} fragments remaining on stack")

    final_nfa = stack[0]
    final_nfa.renumber_states()
    return final_nfa


def compile_regex(regex_str: str) -> NFA:
    """Compiles a regular expression string into a verified ε-NFA."""
    postfix_tokens = parse_regex(regex_str)
    return thompson_construction(postfix_tokens)
