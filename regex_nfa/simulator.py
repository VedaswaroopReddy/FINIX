"""
simulator.py: Non-Deterministic Set-of-States Simulation & ε-Closure Engine.
Runs in O(|w| · |Q| · |δ|) worst-case time without backtracking or determinization overhead.
"""

import time
from typing import Set, List, Dict, Any
from .nfa import State, NFA


class SimulationTraceStep:
    """Detailed record of the automaton configuration at a single character step."""
    def __init__(self, step_idx: int, char: str, before_states: Set[State],
                 direct_targets: Set[State], epsilon_additions: Set[State],
                 after_states: Set[State], accepts_here: bool):
        self.step_idx = step_idx
        self.char = char
        self.before_states = sorted(list(before_states), key=lambda s: s.id)
        self.direct_targets = sorted(list(direct_targets), key=lambda s: s.id)
        self.epsilon_additions = sorted(list(epsilon_additions), key=lambda s: s.id)
        self.after_states = sorted(list(after_states), key=lambda s: s.id)
        self.accepts_here = accepts_here

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step_idx,
            "char": self.char,
            "before_states": [f"q{s.id}" for s in self.before_states],
            "direct_targets": [f"q{s.id}" for s in self.direct_targets],
            "epsilon_additions": [f"q{s.id}" for s in self.epsilon_additions],
            "after_states": [f"q{s.id}" for s in self.after_states],
            "accepts_here": self.accepts_here,
        }


class SimulationResult:
    """Encapsulates the verdict and complete execution history of an NFA run."""
    def __init__(self, input_string: str, is_accepted: bool,
                 initial_states: Set[State], final_states: Set[State],
                 trace: List[SimulationTraceStep], elapsed_ms: float = 0.0):
        self.input_string = input_string
        self.is_accepted = is_accepted
        self.initial_states = sorted(list(initial_states), key=lambda s: s.id)
        self.final_states = sorted(list(final_states), key=lambda s: s.id)
        self.trace = trace
        self.elapsed_ms = elapsed_ms

    def __repr__(self) -> str:
        verdict = "ACCEPTED" if self.is_accepted else "REJECTED"
        return f"SimulationResult(String='{self.input_string}', Result={verdict}, Time={self.elapsed_ms:.3f}ms)"


class NFASimulator:
    """Executes NFA simulation across arbitrary input strings."""

    def __init__(self, nfa: NFA):
        self.nfa = nfa

    @staticmethod
    def epsilon_closure(states: Set[State]) -> Set[State]:
        """
        Computes E(S): the set of all states reachable from S via zero or more ε-transitions.
        Uses Depth-First Search with visited set to handle ε-cycles safely.
        """
        closure = set(states)
        stack = list(states)

        while stack:
            current = stack.pop()
            eps_targets = current.get_epsilon_transitions()
            for target in eps_targets:
                if target not in closure:
                    closure.add(target)
                    stack.append(target)

        return closure

    def move(self, current_states: Set[State], char: str) -> Set[State]:
        """
        Computes MOVE(S, c): direct targets reachable from S on character c
        without taking ε-transitions.
        """
        targets: Set[State] = set()
        for state in current_states:
            for sym, dests in state.transitions.items():
                if sym.matches(char):
                    for d in dests:
                        targets.add(d)
        return targets

    def simulate(self, input_string: str) -> SimulationResult:
        """
        Executes NFA simulation on the given input string from start state.
        Returns a SimulationResult containing the step-by-step trace and acceptance verdict.
        """
        start_time = time.perf_counter()

        # Step 0: Initial active state set = ε-closure({q0})
        current_states = self.epsilon_closure({self.nfa.start_state})
        initial_states = set(current_states)
        trace: List[SimulationTraceStep] = []

        for idx, char in enumerate(input_string):
            direct_targets = self.move(current_states, char)
            after_states = self.epsilon_closure(direct_targets)
            epsilon_additions = after_states - direct_targets
            accepts_here = any(s == self.nfa.accept_state or s.is_accept for s in after_states)

            trace_step = SimulationTraceStep(
                step_idx=idx + 1,
                char=char,
                before_states=current_states,
                direct_targets=direct_targets,
                epsilon_additions=epsilon_additions,
                after_states=after_states,
                accepts_here=accepts_here
            )
            trace.append(trace_step)
            current_states = after_states

            # Early break if no states remain active (stuck state)
            if not current_states:
                # Fill remaining characters as dead steps
                for rem_idx in range(idx + 1, len(input_string)):
                    rem_char = input_string[rem_idx]
                    trace.append(SimulationTraceStep(
                        step_idx=rem_idx + 1,
                        char=rem_char,
                        before_states=set(),
                        direct_targets=set(),
                        epsilon_additions=set(),
                        after_states=set(),
                        accepts_here=False
                    ))
                break

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # String is accepted iff the accept state is present in final active state set
        is_accepted = any(s == self.nfa.accept_state or s.is_accept for s in current_states)

        return SimulationResult(
            input_string=input_string,
            is_accepted=is_accepted,
            initial_states=initial_states,
            final_states=current_states,
            trace=trace,
            elapsed_ms=elapsed_ms
        )

    def matches(self, input_string: str) -> bool:
        """
        High-performance O(|w| · |Q_N|²) boolean acceptance check.
        Operates directly on active state sets with immediate early-exit on dead paths,
        eliminating trace object allocations and list sorting overhead.
        """
        current_states = self.epsilon_closure({self.nfa.start_state})
        accept_id = self.nfa.accept_state.id

        for char in input_string:
            direct_targets = self.move(current_states, char)
            if not direct_targets:
                return False
            current_states = self.epsilon_closure(direct_targets)
            if not current_states:
                return False

        return any(s.id == accept_id or s.is_accept for s in current_states)
