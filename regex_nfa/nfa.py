"""
nfa.py: Formal Automata Data Structures (5-Tuple M = (Q, Σ, δ, q0, F)).
Implements first-class type-safe transition symbols:
  - EPSILON (ε): Empty-string transition
  - CHAR (c): Exact character transition
  - ANY (Σ): Symbolic wildcard matching any character in the alphabet
"""

from typing import Dict, List, Set, Optional, Any, FrozenSet
from collections import deque
from enum import Enum, auto

EPSILON = 'ε'
WILDCARD = 'Σ'  # Symbolic wildcard (Any character)


class SymbolKind(Enum):
    EPSILON = auto()
    CHAR = auto()
    ANY = auto()
    CHARSET = auto()


class Symbol:
    """Type-safe transition symbol representation."""
    def __init__(self, kind: SymbolKind, value: Optional[str] = None, charset: Optional[frozenset] = None):
        self.kind = kind
        self.value = value
        self.charset = charset

    @classmethod
    def epsilon(cls) -> 'Symbol':
        return cls(SymbolKind.EPSILON, EPSILON)

    @classmethod
    def char(cls, value: str) -> 'Symbol':
        return cls(SymbolKind.CHAR, value)

    @classmethod
    def any(cls) -> 'Symbol':
        return cls(SymbolKind.ANY, WILDCARD)

    @classmethod
    def charset(cls, charset: frozenset, display_str: str) -> 'Symbol':
        return cls(SymbolKind.CHARSET, display_str, charset=charset)

    def matches(self, c: str) -> bool:
        """Determines if this symbol consumes character `c`."""
        if self.kind == SymbolKind.EPSILON:
            return False
        if self.kind == SymbolKind.ANY:
            return True
        if self.kind == SymbolKind.CHARSET:
            return self.charset is not None and c in self.charset
        return self.value == c

    def display(self) -> str:
        if self.kind == SymbolKind.EPSILON:
            return EPSILON
        if self.kind == SymbolKind.ANY:
            return WILDCARD
        return self.value or ""

    def __repr__(self) -> str:
        return f"Symbol({self.kind.name}, '{self.display()}')"

    def __eq__(self, other) -> bool:
        if not isinstance(other, Symbol):
            return False
        if self.kind != other.kind:
            return False
        if self.kind == SymbolKind.CHARSET:
            return self.charset == other.charset and self.value == other.value
        return self.value == other.value

    def __hash__(self) -> int:
        if self.kind == SymbolKind.CHARSET:
            return hash((self.kind, self.charset, self.value))
        return hash((self.kind, self.value))


class State:
    """Represents a state in the ε-NFA with transitions."""
    _id_counter = 0

    def __init__(self, state_id: Optional[int] = None, is_accept: bool = False):
        if state_id is None:
            self.id = State._id_counter
            State._id_counter += 1
        else:
            self.id = state_id
        
        self.is_accept = is_accept
        # transitions: Symbol -> List[State]
        self.transitions: Dict[Symbol, List['State']] = {}

    @classmethod
    def reset_counter(cls, start: int = 0):
        cls._id_counter = start

    def add_transition(self, symbol: Symbol, target_state: 'State'):
        """Adds a transition on `symbol` to `target_state`."""
        if symbol not in self.transitions:
            self.transitions[symbol] = []
        if target_state not in self.transitions[symbol]:
            self.transitions[symbol].append(target_state)

    def get_transitions(self, symbol: Symbol) -> List['State']:
        return self.transitions.get(symbol, [])

    def get_epsilon_transitions(self) -> List['State']:
        return self.transitions.get(Symbol.epsilon(), [])

    def __repr__(self) -> str:
        return f"q{self.id}" + ("*" if self.is_accept else "")


class NFA:
    """
    Represents an ε-NFA fragment constructed via Thompson's Construction.
    Guarantees:
      - Exactly 1 start state (q0)
      - Exactly 1 accept state (F = {accept_state})
      - No outgoing transitions from accept_state within the sub-automaton
    """
    def __init__(self, start_state: State, accept_state: State):
        self.start_state = start_state
        self.accept_state = accept_state
        self.accept_state.is_accept = True

    def get_all_states(self) -> Set[State]:
        """Performs optimal O(V + E) BFS traversal to collect all reachable states."""
        visited: Set[State] = set()
        queue = deque([self.start_state])
        visited.add(self.start_state)

        while queue:
            curr = queue.popleft()
            for symbol, targets in curr.transitions.items():
                for tgt in targets:
                    if tgt not in visited:
                        visited.add(tgt)
                        queue.append(tgt)
        return visited

    def get_alphabet(self) -> Set[str]:
        """Returns the set of literal characters (Σ) excluding epsilon, wildcard, and character classes."""
        symbols: Set[str] = set()
        for state in self.get_all_states():
            for symbol in state.transitions:
                if symbol.kind == SymbolKind.CHAR and symbol.value:
                    symbols.add(symbol.value)
        return symbols

    def get_charsets(self) -> Set[Symbol]:
        """Returns the set of distinct character-class symbols used in the NFA."""
        charsets: Set[Symbol] = set()
        for state in self.get_all_states():
            for symbol in state.transitions:
                if symbol.kind == SymbolKind.CHARSET:
                    charsets.add(symbol)
        return charsets

    def has_wildcard(self) -> bool:
        """Returns True if any transition uses the ANY (Σ) wildcard symbol."""
        for state in self.get_all_states():
            for symbol in state.transitions:
                if symbol.kind == SymbolKind.ANY:
                    return True
        return False

    def renumber_states(self):
        """
        Renumbers all states sequentially in BFS topological order:
        q0 is the start state, q_last is the accept state.
        Uses O(V + E) BFS queue with deque.popleft().
        """
        all_states = self.get_all_states()
        visited: Set[State] = set()
        ordered: List[State] = []
        queue = deque([self.start_state])
        visited.add(self.start_state)

        while queue:
            curr = queue.popleft()
            ordered.append(curr)
            for symbol, targets in curr.transitions.items():
                for tgt in targets:
                    if tgt not in visited:
                        visited.add(tgt)
                        queue.append(tgt)

        # Include any remaining states
        for s in all_states:
            if s not in visited:
                ordered.append(s)

        for idx, state in enumerate(ordered):
            state.id = idx

    def generate_transition_table(self) -> str:
        """Generates formal TOC ASCII transition table for the ε-NFA."""
        from .visualizer import Visualizer
        return Visualizer.generate_transition_table(self)

    def generate_layered_svg(self, highlighted_states: Optional[Set[int]] = None) -> str:
        """Generates textbook-grade layered SVG diagram of the ε-NFA."""
        from .visualizer import Visualizer
        return Visualizer.generate_layered_svg(self, highlighted_states)

    def get_metrics(self) -> Dict[str, Any]:
        states = list(self.get_all_states())
        total_transitions = 0
        epsilon_transitions = 0
        for s in states:
            for sym, targets in s.transitions.items():
                total_transitions += len(targets)
                if sym.kind == SymbolKind.EPSILON:
                    epsilon_transitions += len(targets)

        return {
            "state_count": len(states),
            "transition_count": total_transitions,
            "epsilon_transition_count": epsilon_transitions,
            "alphabet_size": len(self.get_alphabet()),
            "start_state": f"q{self.start_state.id}",
            "accept_state": f"q{self.accept_state.id}",
        }

    def __repr__(self) -> str:
        states = self.get_all_states()
        return f"NFA(Q={len(states)}, Start=q{self.start_state.id}, Accept=q{self.accept_state.id})"
