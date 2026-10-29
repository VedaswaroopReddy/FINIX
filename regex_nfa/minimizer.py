"""
minimizer.py: Hopcroft's O(|Σ| · |Q_D| log |Q_D|) DFA Minimization Engine.

Implements canonical automata minimization grounded in the Myhill-Nerode theorem:
  1. Reachability purge: eliminates unreachable states via BFS from start state D0.
  2. Dead-end purge: automatically eliminates non-co-reachable sink states via TRAP normalization.
  3. Hopcroft's partition refinement using the argmin size invariant: O(|Σ| · n log n).
  4. Quotient automaton synthesis with BFS canonical state relabeling.
  5. Deterministic DFA isomorphism and language equivalence proving.
"""

from typing import Dict, List, Set, Tuple, Optional, FrozenSet
from collections import deque
from .dfa import DFA, DFAState


class HopcroftMinimizer:
    """
    Minimizes a Deterministic Finite Automaton (DFA) using Hopcroft's
    partition refinement algorithm with guaranteed O(|Σ| · |Q| log |Q|) complexity.
    """

    TRAP_STATE_ID = -1

    def __init__(self, dfa: DFA):
        self.original_dfa = dfa

    def minimize(self) -> DFA:
        """
        Executes complete minimization pipeline:
          Step 1: Purge unreachable states.
          Step 2: Collect active alphabet.
          Step 3: Precompute forward and inverse transition functions with TRAP state.
          Step 4: Refine partitions using Hopcroft's worklist algorithm.
          Step 5: Synthesize quotient DFA and apply canonical BFS state relabeling.
        """
        # Step 1: Reachability BFS
        reachable_ids = self._get_reachable_states()
        if not reachable_ids:
            return self._build_empty_dfa()

        # Step 2: Alphabet of reachable transitions
        alphabet = sorted(list(self._get_active_alphabet(reachable_ids)))
        if not alphabet:
            alphabet = self.original_dfa.alphabet if self.original_dfa.alphabet else ["a"]

        # Step 3: TRAP state requirement check
        needs_trap = self._check_trap_needed(reachable_ids, alphabet)

        # Step 4: Initial partition sets (F, Q \ F)
        accept_ids, non_accept_ids = self._build_initial_state_sets(reachable_ids, needs_trap)

        # Step 5: Inverse transition lookup table
        inv_trans = self._build_inverse_transitions(reachable_ids, alphabet, needs_trap)

        # Step 6: Initial Partition & Worklist
        partitions, worklist = self._build_initial_worklist(accept_ids, non_accept_ids, alphabet)

        # Step 7: Hopcroft's Partition Refinement Loop
        refined_partitions = self._refine_partitions(partitions, worklist, inv_trans, alphabet)

        # Step 8: Build Quotient Automaton
        return self._synthesize_quotient_dfa(
            partitions=refined_partitions,
            reachable_ids=reachable_ids,
            alphabet=alphabet,
            needs_trap=needs_trap
        )

    def _check_trap_needed(self, reachable_ids: Set[int], alphabet: List[str]) -> bool:
        """Determines if the transition function is partial across reachable states."""
        for sid in reachable_ids:
            state = self.original_dfa.states[sid]
            for ch in alphabet:
                target = state.transitions.get(ch)
                if target is None or target not in reachable_ids:
                    return True
        return False

    def _build_initial_state_sets(
        self, reachable_ids: Set[int], needs_trap: bool
    ) -> Tuple[Set[int], Set[int]]:
        """Splits reachable states into accepting and non-accepting subsets."""
        accept_ids: Set[int] = set()
        non_accept_ids: Set[int] = set()

        for sid in reachable_ids:
            if self.original_dfa.states[sid].is_accept:
                accept_ids.add(sid)
            else:
                non_accept_ids.add(sid)

        if needs_trap:
            non_accept_ids.add(self.TRAP_STATE_ID)

        return accept_ids, non_accept_ids

    def _build_inverse_transitions(
        self, reachable_ids: Set[int], alphabet: List[str], needs_trap: bool
    ) -> Dict[str, Dict[int, Set[int]]]:
        """Precomputes inverse transition map inv[char][target] -> Set[source]."""
        inv_trans: Dict[str, Dict[int, Set[int]]] = {ch: {} for ch in alphabet}
        for ch in alphabet:
            for sid in reachable_ids:
                state = self.original_dfa.states[sid]
                target = state.transitions.get(ch)
                if target is None or target not in reachable_ids:
                    target = self.TRAP_STATE_ID if needs_trap else None

                if target is not None:
                    inv_trans[ch].setdefault(target, set()).add(sid)

            if needs_trap:
                inv_trans[ch].setdefault(self.TRAP_STATE_ID, set()).add(self.TRAP_STATE_ID)

        return inv_trans

    def _build_initial_worklist(
        self, accept_ids: Set[int], non_accept_ids: Set[int], alphabet: List[str]
    ) -> Tuple[List[Set[int]], Set[Tuple[FrozenSet[int], str]]]:
        """Initializes partitions and worklist following the argmin block size invariant."""
        partitions: List[Set[int]] = []
        if accept_ids:
            partitions.append(set(accept_ids))
        if non_accept_ids:
            partitions.append(set(non_accept_ids))

        worklist: Set[Tuple[FrozenSet[int], str]] = set()
        if accept_ids and non_accept_ids:
            smaller_block = accept_ids if len(accept_ids) <= len(non_accept_ids) else non_accept_ids
            frozen_smaller = frozenset(smaller_block)
            for ch in alphabet:
                worklist.add((frozen_smaller, ch))
        elif partitions:
            frozen_p0 = frozenset(partitions[0])
            for ch in alphabet:
                worklist.add((frozen_p0, ch))

        return partitions, worklist

    def _refine_partitions(
        self,
        partitions: List[Set[int]],
        worklist: Set[Tuple[FrozenSet[int], str]],
        inv_trans: Dict[str, Dict[int, Set[int]]],
        alphabet: List[str]
    ) -> List[Set[int]]:
        """Executes Hopcroft's worklist partition refinement loop in O(|Σ| n log n) time."""
        while worklist:
            splitter_block, symbol = worklist.pop()

            x_preimage: Set[int] = set()
            symbol_inv = inv_trans.get(symbol, {})
            for target_state in splitter_block:
                if target_state in symbol_inv:
                    x_preimage.update(symbol_inv[target_state])

            if not x_preimage:
                continue

            new_partitions: List[Set[int]] = []
            for block in partitions:
                intersection = block.intersection(x_preimage)
                difference = block.difference(x_preimage)

                if intersection and difference:
                    new_partitions.append(intersection)
                    new_partitions.append(difference)

                    frozen_y = frozenset(block)
                    frozen_y1 = frozenset(intersection)
                    frozen_y2 = frozenset(difference)

                    for ch in alphabet:
                        if (frozen_y, ch) in worklist:
                            worklist.remove((frozen_y, ch))
                            worklist.add((frozen_y1, ch))
                            worklist.add((frozen_y2, ch))
                        else:
                            if len(intersection) <= len(difference):
                                worklist.add((frozen_y1, ch))
                            else:
                                worklist.add((frozen_y2, ch))
                else:
                    new_partitions.append(block)

            partitions = new_partitions

        return partitions

    def _get_reachable_states(self) -> Set[int]:
        """Performs BFS from original start state to eliminate unreachable states."""
        start_id = self.original_dfa.start_state_id
        if start_id not in self.original_dfa.states:
            return set()

        visited: Set[int] = {start_id}
        queue = deque([start_id])

        while queue:
            curr = queue.popleft()
            state = self.original_dfa.states[curr]
            for target in state.transitions.values():
                if target in self.original_dfa.states and target not in visited:
                    visited.add(target)
                    queue.append(target)

        return visited

    def _get_active_alphabet(self, reachable_ids: Set[int]) -> Set[str]:
        """Collects all input symbols appearing on transitions between reachable states."""
        alphabet: Set[str] = set()
        for sid in reachable_ids:
            state = self.original_dfa.states[sid]
            alphabet.update(state.transitions.keys())
        # Also preserve original display alphabet literals
        if self.original_dfa.alphabet:
            alphabet.update(self.original_dfa.alphabet)
        return alphabet

    def _build_empty_dfa(self) -> DFA:
        """Returns a 1-state minimal DFA rejecting all inputs."""
        d0 = DFAState(state_id=0, nfa_states=frozenset(), is_start=True, is_accept=False)
        return DFA(
            start_state_id=0,
            states={0: d0},
            alphabet=self.original_dfa.alphabet,
            nfa_reference=self.original_dfa.nfa_reference
        )

    def _synthesize_quotient_dfa(
        self,
        partitions: List[Set[int]],
        reachable_ids: Set[int],
        alphabet: List[str],
        needs_trap: bool
    ) -> DFA:
        """
        Synthesizes quotient DFA states from partition blocks and canonicalizes
        state numbering via BFS starting at the start state.
        """
        start_id = self.original_dfa.start_state_id

        # Identify which block contains the TRAP state (if any)
        trap_block: Optional[Set[int]] = None
        if needs_trap:
            for block in partitions:
                if self.TRAP_STATE_ID in block:
                    trap_block = block
                    break

        # Filter out pure trap block from active quotient states
        active_blocks = [b for b in partitions if b is not trap_block]
        if not active_blocks:
            return self._build_empty_dfa()

        # Map each original state to its block index
        state_to_block_idx: Dict[int, int] = {}
        for idx, block in enumerate(active_blocks):
            for sid in block:
                state_to_block_idx[sid] = idx

        # Find block index containing the start state
        start_block_idx = state_to_block_idx.get(start_id)
        if start_block_idx is None:
            # Start state was merged into trap (language is empty)
            return self._build_empty_dfa()

        # Build raw transitions between blocks
        raw_transitions: Dict[int, Dict[str, int]] = {i: {} for i in range(len(active_blocks))}
        block_is_accept: Dict[int, bool] = {}
        block_nfa_states: Dict[int, Set[int]] = {i: set() for i in range(len(active_blocks))}

        for b_idx, block in enumerate(active_blocks):
            # Check accept status and aggregate NFA states
            is_acc = False
            for sid in block:
                if sid != self.TRAP_STATE_ID and sid in self.original_dfa.states:
                    orig_state = self.original_dfa.states[sid]
                    if orig_state.is_accept:
                        is_acc = True
                    block_nfa_states[b_idx].update(orig_state.nfa_states)
            block_is_accept[b_idx] = is_acc

            # Determine outgoing transitions by picking any real state in the block
            rep_state_id = next((s for s in block if s != self.TRAP_STATE_ID), None)
            if rep_state_id is not None:
                rep_state = self.original_dfa.states[rep_state_id]
                for ch, target in rep_state.transitions.items():
                    target_b_idx = state_to_block_idx.get(target)
                    # If target is not in trap block, record transition
                    if target_b_idx is not None:
                        raw_transitions[b_idx][ch] = target_b_idx

        # -------------------------------------------------------------
        # Canonical BFS Relabeling:
        # Renumber states so start state is 0, and subsequent states are
        # numbered in order of discovery via BFS traversing sorted symbols.
        # This produces an isomorphic canonical representation!
        # -------------------------------------------------------------
        canonical_map: Dict[int, int] = {start_block_idx: 0}
        canonical_queue = deque([start_block_idx])
        next_canonical_id = 1

        while canonical_queue:
            curr_b = canonical_queue.popleft()
            # Traverse transitions in deterministic sorted character order
            for ch in sorted(raw_transitions[curr_b].keys()):
                target_b = raw_transitions[curr_b][ch]
                if target_b not in canonical_map:
                    canonical_map[target_b] = next_canonical_id
                    next_canonical_id += 1
                    canonical_queue.append(target_b)

        # Include any remaining disconnected non-trap blocks (if any)
        for b_idx in range(len(active_blocks)):
            if b_idx not in canonical_map:
                canonical_map[b_idx] = next_canonical_id
                next_canonical_id += 1

        # Instantiate canonical DFAState objects
        canonical_states: Dict[int, DFAState] = {}
        for old_b_idx, new_sid in canonical_map.items():
            is_start = (new_sid == 0)
            is_accept = block_is_accept[old_b_idx]
            nfa_subset = frozenset(block_nfa_states[old_b_idx])

            c_state = DFAState(
                state_id=new_sid,
                nfa_states=nfa_subset,
                is_start=is_start,
                is_accept=is_accept
            )
            canonical_states[new_sid] = c_state

        # Populate canonical transitions
        for old_b_idx, new_sid in canonical_map.items():
            c_state = canonical_states[new_sid]
            for ch, old_target_b in raw_transitions[old_b_idx].items():
                new_target_sid = canonical_map[old_target_b]
                c_state.transitions[ch] = new_target_sid

        # Alphabet display: preserve original alphabet order
        display_alphabet = sorted(list(set(
            ch for s in canonical_states.values() for ch in s.transitions.keys()
        )))
        if not display_alphabet:
            display_alphabet = self.original_dfa.alphabet if self.original_dfa.alphabet else ["a"]

        return DFA(
            start_state_id=0,
            states=canonical_states,
            alphabet=display_alphabet,
            nfa_reference=self.original_dfa.nfa_reference
        )


def minimize_dfa(dfa: DFA) -> DFA:
    """Convenience function: runs Hopcroft's minimization on a DFA."""
    minimizer = HopcroftMinimizer(dfa)
    return minimizer.minimize()


def compile_to_minimal_dfa(regex_str: str, anchored: bool = True) -> DFA:
    """End-to-End Pipeline: Regex -> ε-NFA -> Powerset DFA -> Hopcroft Minimal DFA."""
    from .dfa import compile_to_dfa
    dfa = compile_to_dfa(regex_str, anchored=anchored)
    return minimize_dfa(dfa)


def are_isomorphic(dfa1: DFA, dfa2: DFA) -> bool:
    """
    Checks if two minimal DFAs are structurally isomorphic.
    Because HopcroftMinimizer produces canonical BFS-ordered states,
    isomorphism reduces to checking that both DFAs have identical
    state counts, start states, accept states, and transition tables.
    """
    # 1. State counts
    if len(dfa1.states) != len(dfa2.states):
        return False

    # 2. Start state must be 0
    if dfa1.start_state_id != dfa2.start_state_id:
        return False

    # 3. Check every state's accept status and transitions
    for sid, s1 in dfa1.states.items():
        if sid not in dfa2.states:
            return False
        s2 = dfa2.states[sid]
        if s1.is_accept != s2.is_accept:
            return False
        if s1.transitions != s2.transitions:
            return False

    return True


def prove_regex_equivalence(regex1: str, regex2: str) -> Dict[str, Any]:
    """
    Automated Theorem Prover for Regular Expression Equivalence with Witness Synthesis:
      Constructs the Product Automaton M1 x M2 over active alphabet symbols
      and executes BFS to synthesize lexicographically shortest counterexamples in:
        1. L(r1) \\ L(r2) (witness that r1 accepts but r2 rejects)
        2. L(r2) \\ L(r1) (witness that r2 accepts but r1 rejects)
        3. L(r1) ∩ L(r2) (witness of shared language intersection)
    Returns complete proof dictionary with relation verdicts and witnesses.
    """
    m1 = compile_to_minimal_dfa(regex1)
    m2 = compile_to_minimal_dfa(regex2)
    t1, t2 = m1.fast_table, m2.fast_table
    acc1, acc2 = m1.is_accepting, m2.is_accepting

    active_chars = sorted(list({c for s in m1.states.values() for c in s.transitions.keys()} |
                               {c for s in m2.states.values() for c in s.transitions.keys()}))
    if not active_chars:
        active_chars = ["a"]

    visited = set()
    queue = deque([(m1.start_state_id, m2.start_state_id, "")])
    visited.add((m1.start_state_id, m2.start_state_id))

    witness_1_minus_2 = None
    witness_2_minus_1 = None
    witness_intersection = None

    while queue:
        s1, s2, word = queue.popleft()
        a1 = acc1[s1] if s1 != -1 and s1 < len(acc1) else False
        a2 = acc2[s2] if s2 != -1 and s2 < len(acc2) else False

        if a1 and not a2 and witness_1_minus_2 is None:
            witness_1_minus_2 = word
        if not a1 and a2 and witness_2_minus_1 is None:
            witness_2_minus_1 = word
        if a1 and a2 and witness_intersection is None:
            witness_intersection = word

        if witness_1_minus_2 is not None and witness_2_minus_1 is not None and witness_intersection is not None:
            break

        for ch in active_chars:
            code = ord(ch)
            n1 = t1[s1][code] if s1 != -1 and s1 < len(t1) and code < 256 else -1
            n2 = t2[s2][code] if s2 != -1 and s2 < len(t2) and code < 256 else -1
            if n1 == -1 and n2 == -1:
                continue
            pair = (n1, n2)
            if pair not in visited:
                visited.add(pair)
                queue.append((n1, n2, word + ch))

    is_equiv = (witness_1_minus_2 is None and witness_2_minus_1 is None)
    is_subset_1_of_2 = (witness_1_minus_2 is None)
    is_subset_2_of_1 = (witness_2_minus_1 is None)
    is_disjoint = (witness_intersection is None)

    if is_equiv:
        relation = "EQUIVALENT (L1 ≡ L2)"
        proof_lines = [
            f"The languages are EQUIVALENT: L('{regex1}') ≡ L('{regex2}').",
            f"Both reduce to identical canonical minimal DFAs with {len(m1.states)} states.",
            "Symmetric difference L(r1) ⊕ L(r2) = ∅ (No counterexamples exist)."
        ]
    elif is_subset_1_of_2 and not is_subset_2_of_1:
        relation = "STRICT SUBSET (L1 ⊂ L2)"
        w2_disp = "ε (empty string)" if witness_2_minus_1 == "" else f"'{witness_2_minus_1}'"
        proof_lines = [
            f"The languages are NOT EQUIVALENT: L('{regex1}') is a STRICT SUBSET of L('{regex2}'): L1 ⊂ L2.",
            f"Every string in L1 is in L2, but L2 contains additional strings.",
            f"Shortest counterexample in L2 \\ L1: {w2_disp}"
        ]
    elif not is_subset_1_of_2 and is_subset_2_of_1:
        relation = "STRICT SUPERSET (L1 ⊃ L2)"
        w1_disp = "ε (empty string)" if witness_1_minus_2 == "" else f"'{witness_1_minus_2}'"
        proof_lines = [
            f"The languages are NOT EQUIVALENT: L('{regex1}') is a STRICT SUPERSET of L('{regex2}'): L1 ⊃ L2.",
            f"Every string in L2 is in L1, but L1 contains additional strings.",
            f"Shortest counterexample in L1 \\ L2: {w1_disp}"
        ]
    elif is_disjoint:
        relation = "DISJOINT (L1 ∩ L2 = ∅)"
        w1_disp = "ε (empty string)" if witness_1_minus_2 == "" else f"'{witness_1_minus_2}'"
        w2_disp = "ε (empty string)" if witness_2_minus_1 == "" else f"'{witness_2_minus_1}'"
        proof_lines = [
            f"The languages are NOT EQUIVALENT and completely DISJOINT: L1 ∩ L2 = ∅.",
            f"Sample string in L1: {w1_disp}",
            f"Sample string in L2: {w2_disp}"
        ]
    else:
        relation = "OVERLAPPING (L1 ≉ L2)"
        w1_disp = "ε (empty string)" if witness_1_minus_2 == "" else f"'{witness_1_minus_2}'"
        w2_disp = "ε (empty string)" if witness_2_minus_1 == "" else f"'{witness_2_minus_1}'"
        proof_lines = [
            f"The languages OVERLAP but are NOT EQUIVALENT: L1 ≉ L2.",
            f"Shortest counterexample in L1 \\ L2: {w1_disp}",
            f"Shortest counterexample in L2 \\ L1: {w2_disp}",
            f"Shared string in L1 ∩ L2: '{witness_intersection}'"
        ]

    explanation = "\n".join(proof_lines)

    return {
        "is_equivalent": is_equiv,
        "is_subset_l1_of_l2": is_subset_1_of_2,
        "is_subset_l2_of_l1": is_subset_2_of_1,
        "is_disjoint": is_disjoint,
        "relation": relation,
        "explanation": explanation,
        "witness_l1_minus_l2": witness_1_minus_2,
        "witness_l2_minus_l1": witness_2_minus_1,
        "witness_intersection": witness_intersection,
        "m1_states": len(m1.states),
        "m2_states": len(m2.states),
        "states_explored": len(visited)
    }


def are_equivalent_regexes(regex1: str, regex2: str) -> Tuple[bool, str]:
    """
    Automated Theorem Prover for Regular Expression Equivalence:
      L(r1) == L(r2) iff MinimalDFA(r1) ≅ MinimalDFA(r2).
    Returns (verdict, explanation).
    """
    res = prove_regex_equivalence(regex1, regex2)
    return res["is_equivalent"], res["explanation"]
