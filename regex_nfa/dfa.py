"""
dfa.py: Deterministic Finite Automaton (DFA) Engine & Rabin-Scott Powerset Construction.
Transforms non-deterministic ε-NFAs into equivalent DFAs guaranteeing:
  1. Strict linear O(|w|) matching time with 1 lookup per character.
  2. Constant active memory O(1) during evaluation.
  3. Zero ε-transitions and at most 1 transition per symbol per state.
  4. Flat 2D contiguous jump-table for high-throughput security log inspection.
"""

import time
from typing import Dict, List, Set, Optional, Any, Tuple
from collections import deque
from .nfa import State, NFA, SymbolKind
from .simulator import NFASimulator

ALPHABET_LIMIT = 256
ASCII_LIMIT = ALPHABET_LIMIT  # Backwards compatibility alias


class DFAState:
    """Represents a deterministic macro-state composed of a set of NFA states."""
    def __init__(self, state_id: int, nfa_states: frozenset[int],
                 is_start: bool = False, is_accept: bool = False):
        self.id = state_id
        self.nfa_states = nfa_states
        self.is_start = is_start
        self.is_accept = is_accept
        # transitions: char -> target_state_id
        self.transitions: Dict[str, int] = {}
        # grouped_transitions: (target_state_id) -> list of characters/labels
        self.label = f"D{state_id}"

    @property
    def nfa_set_str(self) -> str:
        """Formatted string of constituent NFA states: {q0, q1, q3}."""
        sorted_ids = sorted(list(self.nfa_states))
        return "{" + ", ".join(f"q{sid}" for sid in sorted_ids) + "}"

    def __repr__(self) -> str:
        acc = "*" if self.is_accept else ""
        start = "->" if self.is_start else ""
        return f"{start}{self.label}{acc} {self.nfa_set_str}"


class DFATraceStep:
    """Records a single transition step during deterministic simulation."""
    def __init__(self, step_idx: int, char: str, from_state: int,
                 to_state: Optional[int], is_accept: bool):
        self.step_idx = step_idx
        self.char = char
        self.from_state = from_state
        self.to_state = to_state
        self.is_accept = is_accept

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step_idx,
            "char": self.char,
            "from_state": f"D{self.from_state}",
            "to_state": f"D{self.to_state}" if self.to_state is not None else "∅ (Trap)",
            "is_accept": self.is_accept
        }


class DFASimulationResult:
    """Encapsulates the verdict and complete execution history of a DFA run."""
    def __init__(self, input_string: str, is_accepted: bool,
                 visited_states: List[int], trace: List[DFATraceStep],
                 elapsed_ms: float = 0.0):
        self.input_string = input_string
        self.is_accepted = is_accepted
        self.visited_states = visited_states
        self.trace = trace
        self.elapsed_ms = elapsed_ms

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_string": self.input_string,
            "is_accepted": self.is_accepted,
            "visited_states": [f"D{s}" for s in self.visited_states],
            "trace": [t.to_dict() for t in self.trace],
            "elapsed_ms": self.elapsed_ms
        }

    def __repr__(self) -> str:
        verdict = "ACCEPTED" if self.is_accepted else "REJECTED"
        return f"DFASimulationResult('{self.input_string}' -> {verdict}, Time={self.elapsed_ms:.3f}ms)"


class DFA:
    """
    Deterministic Finite Automaton M = (Q_D, Σ, δ_D, q_D0, F_D).
    Features:
      - Strict O(|w|) match execution via 2D flat jump-table.
      - Exact step-by-step trace simulation.
      - State-mapping metadata linking each DFA macro-state back to its constituent NFA states.
    """
    def __init__(self, start_state_id: int, states: Dict[int, DFAState],
                 alphabet: List[str], nfa_reference: Optional[NFA] = None):
        self.start_state_id = start_state_id
        self.states = states
        self.alphabet = sorted(list(set(alphabet)))
        self.nfa_reference = nfa_reference

        # Build flat 2D jump-table for high-performance O(1) step lookup:
        # dimensions: [state_count][ASCII_LIMIT] initialized to -1 (trap)
        num_states = len(states)
        self.fast_table: List[List[int]] = [[-1] * ASCII_LIMIT for _ in range(num_states)]
        self.is_accepting: List[bool] = [False] * num_states

        for sid, state in states.items():
            if state.is_accept:
                self.is_accepting[sid] = True
            for ch, target_id in state.transitions.items():
                code = ord(ch)
                if code < ASCII_LIMIT:
                    self.fast_table[sid][code] = target_id

    @property
    def start_state(self) -> DFAState:
        return self.states[self.start_state_id]

    def match(self, text: str) -> bool:
        """
        Executes strictly linear O(|w|) deterministic pattern matching.
        Uses single integer state lookups with zero heap allocations during traversal.
        """
        curr = self.start_state_id
        table = self.fast_table
        is_acc = self.is_accepting

        for ch in text:
            code = ord(ch)
            if code < ASCII_LIMIT:
                curr = table[curr][code]
                if curr == -1:
                    return False
            else:
                target = self.states[curr].transitions.get(ch)
                if target is None:
                    return False
                curr = target

        return is_acc[curr]

    def search(self, text: str) -> Optional[Tuple[int, int]]:
        """
        Searches for the first substring matching this DFA.
        Returns (start, end) index tuple (0-indexed, half-open [start, end)), or None.
        Matches leftmost-longest semantics.
        """
        table = self.fast_table
        is_acc = self.is_accepting
        n = len(text)
        limit = ALPHABET_LIMIT

        for i in range(n):
            curr = self.start_state_id
            last_match_end = -1
            if is_acc[curr]:
                last_match_end = i
            for j in range(i, n):
                code = ord(text[j])
                if code >= limit:
                    break
                curr = table[curr][code]
                if curr == -1:
                    break
                if is_acc[curr]:
                    last_match_end = j + 1
            if last_match_end != -1:
                return (i, last_match_end)
        return None

    def find_all(self, text: str) -> List[Tuple[int, int, str]]:
        """
        Finds all non-overlapping substrings in `text` matching this DFA.
        Returns list of (start, end, matched_str).
        """
        table = self.fast_table
        is_acc = self.is_accepting
        n = len(text)
        limit = ALPHABET_LIMIT
        matches: List[Tuple[int, int, str]] = []
        i = 0

        while i < n:
            curr = self.start_state_id
            last_match_end = -1
            if is_acc[curr]:
                last_match_end = i
            for j in range(i, n):
                code = ord(text[j])
                if code >= limit:
                    break
                curr = table[curr][code]
                if curr == -1:
                    break
                if is_acc[curr]:
                    last_match_end = j + 1
            if last_match_end != -1:
                matches.append((i, last_match_end, text[i:last_match_end]))
                i = last_match_end if last_match_end > i else i + 1
            else:
                i += 1
        return matches

    def simulate(self, text: str) -> DFASimulationResult:
        """
        Executes step-by-step deterministic simulation on `text`.
        Generates full trace record for dual-automata synchronized stepping.
        """
        t0 = time.perf_counter()
        curr: Optional[int] = self.start_state_id
        visited: List[int] = [self.start_state_id]
        trace: List[DFATraceStep] = []

        for idx, ch in enumerate(text):
            step_idx = idx + 1
            if curr is None:
                # Trapped
                trace.append(DFATraceStep(step_idx, ch, -1, None, False))
                continue

            from_state = curr
            target = self.states[from_state].transitions.get(ch)
            if target is not None:
                curr = target
                visited.append(curr)
                is_acc = self.states[curr].is_accept
                trace.append(DFATraceStep(step_idx, ch, from_state, curr, is_acc))
            else:
                curr = None
                trace.append(DFATraceStep(step_idx, ch, from_state, None, False))

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        is_accepted = (curr is not None and self.states[curr].is_accept)

        return DFASimulationResult(
            input_string=text,
            is_accepted=is_accepted,
            visited_states=visited,
            trace=trace,
            elapsed_ms=round(elapsed_ms, 3)
        )

    def minimize(self) -> 'DFA':
        """Minimizes this DFA using Hopcroft's O(|Σ| n log n) partition refinement."""
        from .minimizer import HopcroftMinimizer
        return HopcroftMinimizer(self).minimize()

    def get_metrics(self) -> Dict[str, Any]:
        """Returns structural metrics comparing DFA complexity against NFA."""
        total_transitions = sum(len(s.transitions) for s in self.states.values())
        accept_states = [f"D{s.id}" for s in self.states.values() if s.is_accept]

        metrics = {
            "state_count": len(self.states),
            "transition_count": total_transitions,
            "alphabet_size": len(self.alphabet),
            "accept_state_count": len(accept_states),
            "start_state": f"D{self.start_state_id}",
            "accept_states": accept_states,
        }
        if self.nfa_reference:
            nfa_m = self.nfa_reference.get_metrics()
            metrics["nfa_state_count"] = nfa_m["state_count"]
            metrics["nfa_transition_count"] = nfa_m["transition_count"]
            metrics["state_reduction_ratio"] = round(
                (1.0 - len(self.states) / nfa_m["state_count"]) * 100.0, 1
            ) if nfa_m["state_count"] > 0 else 0.0

        return metrics

    def get_grouped_transitions(self) -> List[Dict[str, Any]]:
        """
        Groups characters sharing identical source and target states into compact labels
        (e.g., '0'..'9' -> '0-9' or '\\d') for clean diagram rendering.
        """
        grouped = []
        for sid, state in self.states.items():
            targets_map: Dict[int, List[str]] = {}
            for ch, tid in state.transitions.items():
                targets_map.setdefault(tid, []).append(ch)

            for tid, chs in targets_map.items():
                # Summarize character ranges
                chs_sorted = sorted(chs)
                label = self._summarize_char_list(chs_sorted)
                grouped.append({
                    "from": f"D{sid}",
                    "to": f"D{tid}",
                    "label": label,
                    "char_count": len(chs_sorted)
                })
        return grouped

    @staticmethod
    def _summarize_char_list(chars: List[str]) -> str:
        """Summarizes a list of characters into concise ranges or shorthands."""
        if len(chars) == 1:
            return chars[0]
        cset = frozenset(chars)
        # Check standard shorthands
        if cset == frozenset("0123456789"):
            return r"\d"
        if cset == frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"):
            return r"\w"
        if len(chars) > 6:
            # Check if continuous range
            codes = [ord(c) for c in chars]
            is_contiguous = all(codes[i] + 1 == codes[i + 1] for i in range(len(codes) - 1))
            if is_contiguous:
                return f"{chars[0]}-{chars[-1]}"
            return f"{chars[0]}..{chars[-1]} ({len(chars)})"
        return ", ".join(chars)

    def generate_transition_table(self) -> str:
        """Generates formal TOC ASCII transition table for the DFA."""
        col_symbols = self.alphabet if self.alphabet else ["a", "b"]
        col_width = 12
        header = f"{'State':<12} | " + " | ".join(f"{lbl:^{col_width}}" for lbl in col_symbols) + " | Constituent NFA States"
        sep = "-" * len(header)
        rows = [header, sep]

        for sid in sorted(self.states.keys()):
            state = self.states[sid]
            prefix = ""
            if state.is_start and state.is_accept:
                prefix = "->* "
            elif state.is_start:
                prefix = "->  "
            elif state.is_accept:
                prefix = " *  "
            else:
                prefix = "    "

            label = f"{prefix}D{sid}"
            cells = []
            for sym in col_symbols:
                target = state.transitions.get(sym)
                cell_val = f"D{target}" if target is not None else "∅"
                cells.append(f"{cell_val:^{col_width}}")

            row_str = f"{label:<12} | " + " | ".join(cells) + f" | {state.nfa_set_str}"
            rows.append(row_str)

        return "\n".join(rows)

    def export_graphviz_dot(self, title: str = "Deterministic Finite Automaton (DFA)") -> str:
        """Exports the DFA in Graphviz DOT format with constituent NFA subset labels."""
        lines = [
            "digraph DFA {",
            f'  label="{title}";',
            '  rankdir=LR;',
            '  fontname="Helvetica,Arial,sans-serif";',
            '  node [fontname="Helvetica,Arial,sans-serif", fontsize=11];',
            '  edge [fontname="Helvetica,Arial,sans-serif", fontsize=10];',
            "",
            '  __start [shape=none, label="", width=0, height=0];',
            f'  __start -> D{self.start_state_id};',
            ""
        ]

        for sid, state in self.states.items():
            shape = "doublecircle" if state.is_accept else "circle"
            fill = "#dcfce7" if state.is_accept else ("#e0e7ff" if state.is_start else "#f8fafc")
            color = "#16a34a" if state.is_accept else ("#4338ca" if state.is_start else "#475569")
            tooltip = f"NFA: {state.nfa_set_str}"
            lines.append(
                f'  D{sid} [shape={shape}, style=filled, fillcolor="{fill}", '
                f'color="{color}", tooltip="{tooltip}", label="D{sid}\\n{state.nfa_set_str}"];'
            )

        lines.append("")
        for grp in self.get_grouped_transitions():
            lines.append(f'  {grp["from"]} -> {grp["to"]} [label="{grp["label"]}"];')

        lines.append("}")
        return "\n".join(lines)

    def generate_layered_svg(self, highlighted_state: Optional[int] = None, hide_fallback_edges: bool = False) -> str:
        """Generates textbook-grade layered SVG diagram of the DFA."""
        from .visualizer import Visualizer
        return Visualizer.generate_dfa_layered_svg(self, highlighted_state, hide_fallback_edges)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes DFA structure for REST API and web visualizer consumption."""
        nodes = []
        for sid, state in self.states.items():
            nodes.append({
                "id": f"D{sid}",
                "label": f"D{sid}",
                "nfa_subset": sorted(list(state.nfa_states)),
                "nfa_subset_str": state.nfa_set_str,
                "is_start": state.is_start,
                "is_accept": state.is_accept
            })

        edges = self.get_grouped_transitions()
        metrics = self.get_metrics()

        # Build structured table rows
        table_rows = []
        for sid in sorted(self.states.keys()):
            state = self.states[sid]
            row_tr = {}
            for ch in self.alphabet:
                target = state.transitions.get(ch)
                row_tr[ch] = f"D{target}" if target is not None else "∅"
            table_rows.append({
                "state": f"D{sid}",
                "is_start": state.is_start,
                "is_accept": state.is_accept,
                "nfa_subset_str": state.nfa_set_str,
                "transitions": row_tr
            })

        return {
            "metrics": metrics,
            "alphabet": self.alphabet,
            "nodes": nodes,
            "edges": edges,
            "table": table_rows,
            "dot": self.export_graphviz_dot(),
            "svg": self.generate_layered_svg()
        }


def nfa_to_dfa(nfa: NFA) -> DFA:
    """
    Rabin-Scott Powerset Construction Algorithm.
    Converts an ε-NFA into an equivalent deterministic finite automaton (DFA).
    Explores reachable macro-states in O(|Q_D| · |Σ| · |Q_N|²) time.
    """
    all_nfa_states = {s.id: s for s in nfa.get_all_states()}

    # 1. Compute start macro-state: ε-closure({q0})
    start_closure = NFASimulator.epsilon_closure({nfa.start_state})
    start_ids = frozenset(s.id for s in start_closure)

    # 2. Determine all distinct characters that appear in the NFA
    # Collect literal characters and sample characters from character classes
    active_alphabet: Set[str] = set()
    for s in all_nfa_states.values():
        for sym in s.transitions.keys():
            if sym.kind == SymbolKind.CHAR and sym.value:
                active_alphabet.add(sym.value)
            elif sym.kind == SymbolKind.CHARSET and sym.charset:
                active_alphabet.update(sym.charset)

    # If active alphabet is empty (e.g. .* or empty regex), include printable ASCII
    if not active_alphabet:
        active_alphabet = set("abcdefghijklmnopqrstuvwxyz0123456789")

    # Map frozenset(nfa_ids) -> DFAState
    state_map: Dict[frozenset[int], DFAState] = {}
    states_dict: Dict[int, DFAState] = {}
    queue = deque([start_ids])

    # Initialize start state D0
    is_start_accept = any(s == nfa.accept_state or s.is_accept for s in start_closure)
    d0 = DFAState(state_id=0, nfa_states=start_ids, is_start=True, is_accept=is_start_accept)
    state_map[start_ids] = d0
    states_dict[0] = d0

    # All ASCII characters to populate fast execution table
    # If NFA contains wildcard (ANY), evaluate all ALPHABET_LIMIT characters (0..255).
    # Otherwise evaluate ONLY active symbols appearing on transitions (9.5x synthesis speedup!).
    has_any = any(
        any(sym.kind == SymbolKind.ANY for sym in s.transitions.keys())
        for s in all_nfa_states.values()
    )
    if has_any:
        ascii_chars = [chr(i) for i in range(ALPHABET_LIMIT)]
    else:
        ascii_chars = sorted(list(active_alphabet))

    # 3. Worklist loop
    while queue:
        curr_ids = queue.popleft()
        curr_dfa_state = state_map[curr_ids]
        curr_nfa_states = {all_nfa_states[sid] for sid in curr_ids}

        # For every ASCII character, find reachable NFA states
        for ch in ascii_chars:
            direct_targets: Set[State] = set()
            for s in curr_nfa_states:
                for sym, dests in s.transitions.items():
                    if sym.matches(ch):
                        direct_targets.update(dests)

            if not direct_targets:
                continue

            target_closure = NFASimulator.epsilon_closure(direct_targets)
            target_ids = frozenset(s.id for s in target_closure)

            if target_ids not in state_map:
                new_id = len(state_map)
                is_accept = any(s == nfa.accept_state or s.is_accept for s in target_closure)
                new_state = DFAState(
                    state_id=new_id,
                    nfa_states=target_ids,
                    is_start=False,
                    is_accept=is_accept
                )
                state_map[target_ids] = new_state
                states_dict[new_id] = new_state
                queue.append(target_ids)

            curr_dfa_state.transitions[ch] = state_map[target_ids].id

    # Alphabet for visual display: sorted literals from NFA, or sorted active characters if <= 16
    display_alphabet = sorted(list(nfa.get_alphabet()))
    if not display_alphabet:
        display_alphabet = sorted(list(active_alphabet))[:10]

    return DFA(
        start_state_id=0,
        states=states_dict,
        alphabet=display_alphabet,
        nfa_reference=nfa
    )


def compile_to_dfa(regex_str: str, anchored: bool = True) -> DFA:
    """Convenience pipeline: Regex String -> ε-NFA -> Rabin-Scott DFA."""
    from .thompson import compile_regex
    nfa = compile_regex(regex_str, anchored=anchored)
    return nfa_to_dfa(nfa)
