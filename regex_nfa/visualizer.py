"""
visualizer.py: State Transition Table Generator, ASCII Trace Visualizer, and Graphviz DOT Exporter.
Produces academic-grade diagrams and tables for slide presentations.
"""

from typing import List, Set, Dict, Any, Tuple, Optional
from collections import deque
from .nfa import State, NFA, Symbol, EPSILON
from .simulator import SimulationResult


class Visualizer:
    """Provides formatting and export utilities for NFAs and simulation results."""

    @staticmethod
    def format_compact_edge_label(symbols: List[str]) -> Tuple[str, str]:
        """
        Formats multi-symbol transitions into compact, high-legibility badges.
        Long symbol sets or minterm complements collapse into 'other (N)'
        with full expansion preserved for SVG <title> hover tooltips.
        """
        if not symbols:
            return ("", "")
        if len(symbols) == 1:
            return (symbols[0], symbols[0])
        joined = ", ".join(symbols)
        if len(symbols) <= 3 and len(joined) <= 14:
            return (joined, joined)
        has_special = any("Σ" in s or "other" in s or "\\" in s or "[^" in s for s in symbols)
        if has_special or len(symbols) >= 5:
            return (f"other ({len(symbols)})", joined)
        return (f"{symbols[0]},{symbols[1]}+{len(symbols) - 2}", joined)

    @staticmethod
    def generate_transition_table(nfa: NFA) -> str:
        """
        Generates a formal ASCII State Transition Table formatted according to TOC conventions:
        - `->` denotes Start State
        - `*` denotes Accept State
        - `∅` denotes no transition
        """
        states = sorted(list(nfa.get_all_states()), key=lambda s: s.id)
        literal_symbols = sorted(list(nfa.get_alphabet()))
        has_wildcard = nfa.has_wildcard()

        # Build column list: [ε] + sorted literals + sorted charsets + [Σ] (if wildcard present)
        columns: List[Symbol] = [Symbol.epsilon()]
        for ch in literal_symbols:
            columns.append(Symbol.char(ch))
        for cs in sorted(list(nfa.get_charsets()), key=lambda s: s.display()):
            columns.append(cs)
        if has_wildcard:
            columns.append(Symbol.any())

        col_labels = [s.display() for s in columns]
        col_width = 14
        header = f"{'State':<10} | " + " | ".join(f"{lbl:^{col_width}}" for lbl in col_labels)
        separator = "-" * len(header)

        rows = [header, separator]

        for state in states:
            prefix = ""
            if state == nfa.start_state and (state.is_accept or state == nfa.accept_state):
                prefix = "->* "
            elif state == nfa.start_state:
                prefix = "->  "
            elif state.is_accept or state == nfa.accept_state:
                prefix = " *  "
            else:
                prefix = "    "

            state_label = f"{prefix}q{state.id}"
            cell_strs = []

            for sym in columns:
                targets = state.get_transitions(sym)
                if targets:
                    target_str = "{" + ", ".join(f"q{t.id}" for t in sorted(targets, key=lambda s: s.id)) + "}"
                else:
                    target_str = "∅"
                cell_strs.append(f"{target_str:^{col_width}}")

            row_str = f"{state_label:<10} | " + " | ".join(cell_strs)
            rows.append(row_str)

        return "\n".join(rows)

    @staticmethod
    def format_simulation_trace(result: SimulationResult) -> str:
        """
        Formats a simulation execution trace into an ASCII table with ε-additions breakdown.
        """
        lines = []
        init_str = "{" + ", ".join(f"q{s.id}" for s in result.initial_states) + "}"
        lines.append(f"Initial State(s) (ε-closure of start): {init_str}")
        lines.append("")

        header = f"{'Step':<5} | {'Char':<6} | {'Active (Before)':<22} | {'Direct MOVE':<18} | {'ε-Additions':<18} | {'Active (After ε)':<22}"
        sep = "-" * len(header)
        lines.append(header)
        lines.append(sep)

        for step in result.trace:
            before = "{" + ", ".join(f"q{s.id}" for s in step.before_states) + "}"
            direct = "{" + ", ".join(f"q{s.id}" for s in step.direct_targets) + "}" if step.direct_targets else "∅"
            eps_add = "{" + ", ".join(f"q{s.id}" for s in step.epsilon_additions) + "}" if step.epsilon_additions else "∅"
            after = "{" + ", ".join(f"q{s.id}" for s in step.after_states) + "}" if step.after_states else "∅ (Dead)"

            char_disp = f"'{step.char}'"
            lines.append(f"{step.step_idx:<5} | {char_disp:<6} | {before:<22} | {direct:<18} | {eps_add:<18} | {after:<22}")

        lines.append(sep)
        final_str = "{" + ", ".join(f"q{s.id}" for s in result.final_states) + "}" if result.final_states else "∅"
        lines.append(f"Final State Set : {final_str}")
        verdict = "✓ ACCEPTED (Contains accept state)" if result.is_accepted else "✗ REJECTED (Accept state not reached)"
        lines.append(f"Verdict         : {verdict} (Execution time: {result.elapsed_ms:.3f} ms)")

        return "\n".join(lines)

    @staticmethod
    def export_graphviz_dot(nfa: NFA, title: str = "ε-NFA") -> str:
        """
        Generates clean Graphviz DOT code for high-resolution vector diagram generation.
        """
        states = sorted(list(nfa.get_all_states()), key=lambda s: s.id)
        dot_lines = [
            "digraph NFA {",
            "    rankdir=LR;",
            f'    label="{title}";',
            '    labelloc="t";',
            '    node [shape = circle, fontname="Helvetica", style=filled, fillcolor="#1e293b", fontcolor="#f8fafc", color="#38bdf8"];',
            '    edge [fontname="Helvetica", color="#94a3b8", fontcolor="#38bdf8"];',
            "",
            "    // Invisible start marker",
            "    __start__ [shape=point, style=invis];",
            f"    __start__ -> q{nfa.start_state.id};",
            "",
            "    // Accept states",
        ]

        for s in states:
            if s.is_accept or s == nfa.accept_state:
                dot_lines.append(f'    q{s.id} [shape = doublecircle, fillcolor="#14532d", color="#22c55e"];')

        dot_lines.append("")
        dot_lines.append("    // Transitions")

        # Group transitions between same pair of states
        transition_map: Dict[Tuple[int, int], List[str]] = {}
        for s in states:
            for sym, targets in s.transitions.items():
                for tgt in targets:
                    key = (s.id, tgt.id)
                    if key not in transition_map:
                        transition_map[key] = []
                    transition_map[key].append(sym.display())

        for (src, tgt), symbols in transition_map.items():
            label = ", ".join(symbols)
            color_style = ' [color="#818cf8", fontcolor="#818cf8"]' if EPSILON in symbols else ''
            dot_lines.append(f'    q{src} -> q{tgt} [label = "{label}"]{color_style};')

        dot_lines.append("}")
        return "\n".join(dot_lines)

    @staticmethod
    def generate_layered_svg(nfa: NFA, highlighted_states: Set[int] = None) -> str:
        """
        Generates a publication-grade, self-contained SVG diagram of the ε-NFA
        matching the clean textbook aesthetic of FINIX.
        - Start state: soft indigo with indicator
        - Normal states: clean slate with crisp borders
        - Accept state: double green ring
        - Edges: solid slate for symbols, dashed violet for ε-transitions
        - Strict Perimeter Routing: backward and bypass edges route strictly outside node rows
        - Source-Anchored Labeling (t=0.16) for backward loops eliminating mid-air collisions
        """
        import math
        highlighted = highlighted_states or set()

        def _escape_xml(s: str) -> str:
            return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

        # 1. Assign columns via BFS distance from start state
        column: Dict[State, int] = {nfa.start_state: 0}
        queue = deque([nfa.start_state])
        while queue:
            curr = queue.popleft()
            c = column[curr]
            for sym, targets in curr.transitions.items():
                for t in targets:
                    if t not in column:
                        column[t] = c + 1
                        queue.append(t)

        for s in nfa.get_all_states():
            if s not in column:
                column[s] = 0

        max_col = max(column.values()) if column else 0
        cols: List[List[State]] = [[] for _ in range(max_col + 1)]
        for s in sorted(list(nfa.get_all_states()), key=lambda x: x.id):
            cols[column[s]].append(s)

        # 2. Barycenter row ordering within columns to minimize edge crossings
        row_idx: Dict[State, int] = {}
        for c_idx, col_states in enumerate(cols):
            if c_idx > 0:
                def get_barycenter(st: State) -> float:
                    preds = [p for p in nfa.get_all_states() if column.get(p) == c_idx - 1 and any(st in tgts for tgts in p.transitions.values())]
                    if not preds:
                        return float(st.id)
                    return sum(row_idx.get(p, 0) for p in preds) / len(preds)
                col_states.sort(key=lambda s: (get_barycenter(s), s.id))
            for r_idx, st in enumerate(col_states):
                row_idx[st] = r_idx

        # 3. Geometric layout constants
        NODE_RADIUS = 22
        COLUMN_GAP = 105
        ROW_GAP = 75
        PADDING_X = 75
        PADDING_Y = 55

        max_rows = max(len(c) for c in cols) if cols else 1
        height = PADDING_Y * 2 + max(1, max_rows - 1) * ROW_GAP + NODE_RADIUS * 2
        width = PADDING_X * 2 + max(1, len(cols) - 1) * COLUMN_GAP + NODE_RADIUS * 2

        node_pos: Dict[State, Tuple[float, float, int]] = {}
        for c_idx, col_states in enumerate(cols):
            col_height = (len(col_states) - 1) * ROW_GAP
            top = height / 2.0 - col_height / 2.0
            for r_idx, st in enumerate(col_states):
                x = PADDING_X + NODE_RADIUS + c_idx * COLUMN_GAP
                y = top + r_idx * ROW_GAP
                node_pos[st] = (x, y, c_idx)

        all_ys = [pos[1] for pos in node_pos.values()]
        min_graph_y = min(all_ys) if all_ys else 0.0
        max_graph_y = max(all_ys) if all_ys else float(height)
        mid_graph_y = (min_graph_y + max_graph_y) / 2.0

        # 4. Helpers for edge trimming
        def point_towards(x1: float, y1: float, x2: float, y2: float, dist: float) -> Tuple[float, float]:
            dx = x2 - x1
            dy = y2 - y1
            d = math.hypot(dx, dy) or 1.0
            return (x1 + (dx / d) * dist, y1 + (dy / d) * dist)

        # Group transitions between same pair of states
        pair_edges: Dict[Tuple[State, State], List[str]] = {}
        for s in nfa.get_all_states():
            for sym, targets in s.transitions.items():
                for tgt in targets:
                    key = (s, tgt)
                    if key not in pair_edges:
                        pair_edges[key] = []
                    label = sym.display()
                    if label not in pair_edges[key]:
                        pair_edges[key].append(label)

        # Precalculate bounds for curve clipping prevention
        min_y_bound = 0.0
        max_y_bound = float(height)

        edge_render_data = []
        back_edge_counter = 0
        forward_bypass_counter = 0

        for (u, v), sym_labels in pair_edges.items():
            ux, uy, u_col = node_pos[u]
            vx, vy, v_col = node_pos[v]

            is_eps = (sym_labels == [EPSILON])
            edge_color = "#c084fc" if is_eps else "#94a3b8"
            marker_id = "arrow-eps" if is_eps else "arrow-solid"
            dash_style = ' stroke-dasharray="4 3"' if is_eps else ''
            disp_label, full_label = Visualizer.format_compact_edge_label(sym_labels)

            if u == v:
                # Self-loop: smooth cubic bezier arc above the state
                top_y = uy - NODE_RADIUS
                loop_r = 22.0
                path_d = f"M {ux - 12.0:.1f} {top_y:.1f} C {ux - 32.0:.1f} {top_y - loop_r * 2.1:.1f}, {ux + 32.0:.1f} {top_y - loop_r * 2.1:.1f}, {ux + 12.0:.1f} {top_y:.1f}"
                lbl_x = ux
                lbl_y = top_y - loop_r * 1.9
                min_y_bound = min(min_y_bound, lbl_y - 16.0)
                edge_render_data.append({
                    "path_d": path_d,
                    "edge_color": edge_color,
                    "dash_style": dash_style,
                    "marker_id": marker_id,
                    "lbl_x": lbl_x,
                    "lbl_y": lbl_y,
                    "label_text": disp_label,
                    "full_label": full_label,
                    "is_eps": is_eps
                })
                continue

            is_backward = (v_col <= u_col)
            span = abs(v_col - u_col)

            if not is_backward and span == 1:
                # Direct straight forward edge
                x1, y1 = point_towards(ux, uy, vx, vy, NODE_RADIUS)
                x2, y2 = point_towards(vx, vy, ux, uy, NODE_RADIUS + 4.0)
                path_d = f"M {x1:.1f} {y1:.1f} L {x2:.1f} {y2:.1f}"
                lbl_x = (x1 + x2) / 2.0
                lbl_y = (y1 + y2) / 2.0 - 8.0
            elif is_backward:
                # Strict Perimeter Clearance for backward edges
                arc_over = (vy <= mid_graph_y)
                cx = (ux + vx) / 2.0
                stagger = (back_edge_counter % 3) * 14.0
                back_edge_counter += 1
                if arc_over:
                    cy = min_graph_y - NODE_RADIUS - 36.0 - span * 9.0 - stagger
                else:
                    cy = max_graph_y + NODE_RADIUS + 36.0 + span * 9.0 + stagger

                min_y_bound = min(min_y_bound, cy - 26.0)
                max_y_bound = max(max_y_bound, cy + 26.0)

                x1, y1 = point_towards(ux, uy, cx, cy, NODE_RADIUS)
                x2, y2 = point_towards(vx, vy, cx, cy, NODE_RADIUS + 4.0)
                path_d = f"M {x1:.1f} {y1:.1f} Q {cx:.1f} {cy:.1f} {x2:.1f} {y2:.1f}"

                # Source-anchored label (t = 0.16) so each state's badge sits adjacent to its source
                t = 0.16
                lbl_x = (1 - t)**2 * x1 + 2 * (1 - t) * t * cx + t**2 * x2
                lbl_y = (1 - t)**2 * y1 + 2 * (1 - t) * t * cy + t**2 * y2 + (-8.0 if arc_over else 8.0)
            else:
                # Forward bypass (span > 1): strict perimeter routing outside node rows
                arc_over = (min(uy, vy) <= mid_graph_y)
                cx = (ux + vx) / 2.0
                stagger = (forward_bypass_counter % 2) * 12.0
                forward_bypass_counter += 1
                if arc_over:
                    cy = min_graph_y - NODE_RADIUS - 32.0 - span * 7.0 - stagger
                    min_y_bound = min(min_y_bound, cy - 22.0)
                else:
                    cy = max_graph_y + NODE_RADIUS + 32.0 + span * 7.0 + stagger
                    max_y_bound = max(max_y_bound, cy + 22.0)

                x1, y1 = point_towards(ux, uy, cx, cy, NODE_RADIUS)
                x2, y2 = point_towards(vx, vy, cx, cy, NODE_RADIUS + 4.0)
                path_d = f"M {x1:.1f} {y1:.1f} Q {cx:.1f} {cy:.1f} {x2:.1f} {y2:.1f}"

                # Target-anchored label (t = 0.84)
                t = 0.84
                lbl_x = (1 - t)**2 * x1 + 2 * (1 - t) * t * cx + t**2 * x2
                lbl_y = (1 - t)**2 * y1 + 2 * (1 - t) * t * cy + t**2 * y2 + (-8.0 if arc_over else 8.0)

            edge_render_data.append({
                "path_d": path_d,
                "edge_color": edge_color,
                "dash_style": dash_style,
                "marker_id": marker_id,
                "lbl_x": lbl_x,
                "lbl_y": lbl_y,
                "label_text": disp_label,
                "full_label": full_label,
                "is_eps": is_eps
            })

        # Calculate exact bounding box so no text or arrow is ever clipped
        all_xs = [pos[0] for pos in node_pos.values()]
        min_x = min(all_xs) - NODE_RADIUS - 75.0
        max_x = max(all_xs) + NODE_RADIUS + 35.0
        min_y = min(min_y_bound, min_graph_y - NODE_RADIUS - 25.0)
        max_y = max(max_y_bound, max_graph_y + NODE_RADIUS + 25.0)
        view_w = max(max_x - min_x, 140.0)
        view_h = max(max_y - min_y, 90.0)

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{min_x:.1f} {min_y:.1f} {view_w:.1f} {view_h:.1f}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet" class="automata-svg w-full h-auto select-none font-sans" role="img" aria-label="Generated ε-NFA" style="color-scheme: dark; background: transparent; display: block; margin: 0 auto;">',
            '  <defs>',
            '    <filter id="glow-gold" x="-30%" y="-30%" width="160%" height="160%">',
            '      <feGaussianBlur stdDeviation="4" result="blur" />',
            '      <feComposite in="SourceGraphic" in2="blur" operator="over" />',
            '    </filter>',
            '    <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">',
            '      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#94a3b8" />',
            '    </marker>',
            '    <marker id="arrow-solid" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">',
            '      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#94a3b8" />',
            '    </marker>',
            '    <marker id="arrow-eps" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">',
            '      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#c084fc" />',
            '    </marker>',
            '    <marker id="arrow-start" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">',
            '      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#38bdf8" />',
            '    </marker>',
            '  </defs>',
            '  <g class="edges">'
        ]

        # 5. Render edges
        for ed in edge_render_data:
            svg_parts.append(
                f'    <path d="{ed["path_d"]}" fill="none" stroke="{ed["edge_color"]}" stroke-width="1.8"{ed["dash_style"]} marker-end="url(#{ed["marker_id"]})" />'
            )
            pill_w = max(16.0, len(ed["label_text"]) * 7.5 + 8.0)
            svg_parts.append(
                f'    <rect x="{ed["lbl_x"] - pill_w/2:.1f}" y="{ed["lbl_y"] - 8:.1f}" width="{pill_w:.1f}" height="15" rx="3" fill="#090d16" fill-opacity="0.88" />'
            )
            font_style = 'italic' if ed["is_eps"] else 'normal'
            font_weight = '600'
            text_color = '#c084fc' if ed["is_eps"] else '#38bdf8'
            title_tag = f'<title>Transition on: {_escape_xml(ed["full_label"])}</title>'
            svg_parts.append(
                f'    <text x="{ed["lbl_x"]:.1f}" y="{ed["lbl_y"] + 3.5:.1f}" text-anchor="middle" fill="{text_color}" font-style="{font_style}" font-weight="{font_weight}" font-size="11" font-family="system-ui, sans-serif">{title_tag}{_escape_xml(ed["label_text"])}</text>'
            )

        svg_parts.append('  </g>')
        svg_parts.append('  <g class="nodes">')

        # 6. Start indicator arrow into q0 with no overlap
        sx, sy, _ = node_pos[nfa.start_state]
        svg_parts.append(
            f'    <line x1="{sx - NODE_RADIUS - 40:.1f}" y1="{sy:.1f}" x2="{sx - NODE_RADIUS - 4:.1f}" y2="{sy:.1f}" stroke="#38bdf8" stroke-width="2.0" marker-end="url(#arrow-start)" />'
        )
        svg_parts.append(
            f'    <text x="{sx - NODE_RADIUS - 46:.1f}" y="{sy + 4:.1f}" text-anchor="end" fill="#38bdf8" font-size="11" font-weight="700" letter-spacing="0.04em" font-family="system-ui, sans-serif">START</text>'
        )

        # 7. Render states
        for st, (x, y, _) in node_pos.items():
            is_st_start = (st == nfa.start_state)
            is_st_accept = (st == nfa.accept_state or st.is_accept)
            is_active = (st.id in highlighted)

            if is_active:
                fill_color = "#78350f"
                border_color = "#fbbf24"
                text_color = "#fef08a"
                stroke_w = 2.5
                filter_attr = ' filter="url(#glow-gold)"'
            elif is_st_accept:
                fill_color = "#064e3b"
                border_color = "#22c55e"
                text_color = "#86efac"
                stroke_w = 2.0
                filter_attr = ''
            elif is_st_start:
                fill_color = "#1e3a8a"
                border_color = "#38bdf8"
                text_color = "#ffffff"
                stroke_w = 2.0
                filter_attr = ''
            else:
                fill_color = "#1e293b"
                border_color = "#475569"
                text_color = "#f8fafc"
                stroke_w = 1.6
                filter_attr = ''

            svg_parts.append(
                f'    <circle id="node-q{st.id}" data-state-id="{st.id}" data-is-start="{str(is_st_start).lower()}" data-is-accept="{str(is_st_accept).lower()}" cx="{x:.1f}" cy="{y:.1f}" r="{NODE_RADIUS}" fill="{fill_color}" stroke="{border_color}" stroke-width="{stroke_w}"{filter_attr} />'
            )
            if is_st_accept:
                svg_parts.append(
                    f'    <circle id="inner-q{st.id}" data-state-id="{st.id}" cx="{x:.1f}" cy="{y:.1f}" r="{NODE_RADIUS - 4}" fill="none" stroke="#22c55e" stroke-width="1.4" />'
                )

            svg_parts.append(
                f'    <text x="{x:.1f}" y="{y + 4.0:.1f}" text-anchor="middle" fill="{text_color}" font-size="12" font-weight="600" font-family="system-ui, sans-serif">q{st.id}</text>'
            )

        svg_parts.append('  </g>')
        svg_parts.append('</svg>')

        return "\n".join(svg_parts)

    @staticmethod
    def generate_dfa_layered_svg(dfa: Any, highlighted_state: Optional[int] = None, hide_fallback_edges: bool = False) -> str:
        """
        Generates a publication-grade SVG diagram of the Deterministic Finite Automaton (DFA).
        Displays canonical macro-state names (D0, D1, ...) alongside constituent NFA subsets ({q0, q1, ...}).
        - Strict Perimeter Routing: backward loops and forward bypasses route outside node rows
        - Source-Anchored Labeling (t=0.16): spreads backward loop labels with zero mid-air pile-ups
        - Compact Badge Compacting: multi-symbol sets collapse into 'other (N)' with full tooltips
        - Clean Spine Support: hide_fallback_edges suppresses repetitive resets to start state
        """
        import math

        def _escape_xml(s: str) -> str:
            return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

        def point_towards(x1: float, y1: float, x2: float, y2: float, dist: float) -> Tuple[float, float]:
            dx = x2 - x1
            dy = y2 - y1
            d = math.hypot(dx, dy) or 1.0
            return (x1 + (dx / d) * dist, y1 + (dy / d) * dist)

        start_id = dfa.start_state_id
        all_sids = sorted(list(dfa.states.keys()))

        # 1. Assign columns via BFS from start state
        column: Dict[int, int] = {start_id: 0}
        queue = deque([start_id])
        while queue:
            curr = queue.popleft()
            c = column[curr]
            st = dfa.states[curr]
            for target_id in st.transitions.values():
                if target_id not in column:
                    column[target_id] = c + 1
                    queue.append(target_id)

        for sid in all_sids:
            if sid not in column:
                column[sid] = 0

        max_col = max(column.values()) if column else 0
        cols: List[List[int]] = [[] for _ in range(max_col + 1)]
        for sid in all_sids:
            cols[column[sid]].append(sid)

        # 2. Barycenter row ordering within columns
        row_idx: Dict[int, int] = {}
        for c_idx, col_sids in enumerate(cols):
            if c_idx > 0:
                def get_dfa_barycenter(sid: int) -> float:
                    preds = [
                        p for p in all_sids
                        if column.get(p) == c_idx - 1 and any(sid == t for t in dfa.states[p].transitions.values())
                    ]
                    if not preds:
                        return float(sid)
                    return sum(row_idx.get(p, 0) for p in preds) / len(preds)
                col_sids.sort(key=lambda s: (get_dfa_barycenter(s), s))
            for r_idx, sid in enumerate(col_sids):
                row_idx[sid] = r_idx

        # 3. Geometric layout constants
        NODE_RADIUS = 24
        COLUMN_GAP = 120
        ROW_GAP = 85
        PADDING_X = 80
        PADDING_Y = 60

        max_rows = max(len(c) for c in cols) if cols else 1
        height = PADDING_Y * 2 + max(1, max_rows - 1) * ROW_GAP + NODE_RADIUS * 2
        width = PADDING_X * 2 + max(1, len(cols) - 1) * COLUMN_GAP + NODE_RADIUS * 2

        node_pos: Dict[int, Tuple[float, float]] = {}
        for c_idx, col_sids in enumerate(cols):
            col_height = (len(col_sids) - 1) * ROW_GAP
            top = height / 2.0 - col_height / 2.0
            for r_idx, sid in enumerate(col_sids):
                x = PADDING_X + c_idx * COLUMN_GAP
                y = top + r_idx * ROW_GAP
                node_pos[sid] = (x, y)

        # Precompute edge bounds
        all_xs = [pos[0] for pos in node_pos.values()]
        all_ys = [pos[1] for pos in node_pos.values()]
        min_graph_y = min(all_ys) if all_ys else 0.0
        max_graph_y = max(all_ys) if all_ys else float(height)
        mid_graph_y = (min_graph_y + max_graph_y) / 2.0

        min_y_bound = min_graph_y - NODE_RADIUS - 30.0
        max_y_bound = max_graph_y + NODE_RADIUS + 30.0

        # Group edges and prepare rendering data
        grouped_edges = dfa.get_grouped_transitions()
        edge_render_data = []

        back_edge_counter = 0
        forward_bypass_counter = 0

        for edge_idx, edge in enumerate(grouped_edges):
            src_id = int(edge["from"].replace("D", ""))
            tgt_id = int(edge["to"].replace("D", ""))
            label = edge["label"]

            if src_id not in node_pos or tgt_id not in node_pos:
                continue

            # Fallback suppression for Clean Spine view
            if hide_fallback_edges and src_id != start_id and tgt_id == start_id:
                continue

            raw_syms = [s.strip() for s in label.split(",") if s.strip()]
            disp_label, full_label = Visualizer.format_compact_edge_label(raw_syms)

            x1, y1 = node_pos[src_id]
            x2, y2 = node_pos[tgt_id]

            if src_id == tgt_id:
                # Self Loop arc above the node
                loop_r = 24.0
                top_y = y1 - NODE_RADIUS
                p1_x = x1 - 14.0
                p2_x = x1 + 14.0
                path_d = f"M {p1_x:.1f} {top_y:.1f} C {x1 - 36.0:.1f} {top_y - loop_r * 2.2:.1f}, {x1 + 36.0:.1f} {top_y - loop_r * 2.2:.1f}, {p2_x:.1f} {top_y:.1f}"
                lbl_x = x1
                lbl_y = top_y - loop_r * 2.2 + 3.0
                min_y_bound = min(min_y_bound, lbl_y - 15.0)

                edge_render_data.append({
                    "path_d": path_d,
                    "lbl_x": lbl_x,
                    "lbl_y": lbl_y,
                    "label": disp_label,
                    "full_label": full_label
                })
            else:
                c1 = column.get(src_id, 0)
                c2 = column.get(tgt_id, 0)
                is_back = (c2 <= c1)
                span = abs(c2 - c1)

                if is_back:
                    # Strict Perimeter Clearance for backward loops
                    col_diff = abs(c1 - c2)
                    arc_over = (y2 <= mid_graph_y)
                    stagger = (back_edge_counter % 3) * 14.0
                    back_edge_counter += 1
                    if arc_over:
                        ctrl_y = min_graph_y - NODE_RADIUS - 38.0 - col_diff * 8.0 - stagger
                        min_y_bound = min(min_y_bound, ctrl_y - 24.0)
                    else:
                        ctrl_y = max_graph_y + NODE_RADIUS + 38.0 + col_diff * 8.0 + stagger
                        max_y_bound = max(max_y_bound, ctrl_y + 24.0)

                    ctrl_x = (x1 + x2) / 2.0
                    start_x, start_y = point_towards(x1, y1, ctrl_x, ctrl_y, NODE_RADIUS)
                    end_x, end_y = point_towards(x2, y2, ctrl_x, ctrl_y, NODE_RADIUS + 3.0)
                    path_d = f"M {start_x:.1f} {start_y:.1f} Q {ctrl_x:.1f} {ctrl_y:.1f} {end_x:.1f} {end_y:.1f}"

                    # Source-anchored label (t = 0.16) so each state's label is adjacent to itself
                    t = 0.16
                    lbl_x = (1 - t)**2 * start_x + 2 * (1 - t) * t * ctrl_x + t**2 * end_x
                    lbl_y = (1 - t)**2 * start_y + 2 * (1 - t) * t * ctrl_y + t**2 * end_y + (-8.0 if arc_over else 8.0)
                elif span > 1:
                    # Strict Perimeter Clearance for forward bypass edges
                    arc_over = (min(y1, y2) <= mid_graph_y)
                    stagger = (forward_bypass_counter % 2) * 12.0
                    forward_bypass_counter += 1
                    if arc_over:
                        ctrl_y = min_graph_y - NODE_RADIUS - 34.0 - span * 7.0 - stagger
                        min_y_bound = min(min_y_bound, ctrl_y - 24.0)
                    else:
                        ctrl_y = max_graph_y + NODE_RADIUS + 34.0 + span * 7.0 + stagger
                        max_y_bound = max(max_y_bound, ctrl_y + 24.0)

                    ctrl_x = (x1 + x2) / 2.0
                    start_x, start_y = point_towards(x1, y1, ctrl_x, ctrl_y, NODE_RADIUS)
                    end_x, end_y = point_towards(x2, y2, ctrl_x, ctrl_y, NODE_RADIUS + 3.0)
                    path_d = f"M {start_x:.1f} {start_y:.1f} Q {ctrl_x:.1f} {ctrl_y:.1f} {end_x:.1f} {end_y:.1f}"

                    # Target-anchored label (t = 0.84)
                    t = 0.84
                    lbl_x = (1 - t)**2 * start_x + 2 * (1 - t) * t * ctrl_x + t**2 * end_x
                    lbl_y = (1 - t)**2 * start_y + 2 * (1 - t) * t * ctrl_y + t**2 * end_y + (-8.0 if arc_over else 8.0)
                else:
                    # Direct straight adjacent edge
                    start_x, start_y = point_towards(x1, y1, x2, y2, NODE_RADIUS)
                    end_x, end_y = point_towards(x2, y2, x1, y1, NODE_RADIUS + 3.0)
                    path_d = f"M {start_x:.1f} {start_y:.1f} L {end_x:.1f} {end_y:.1f}"
                    lbl_x = (start_x + end_x) / 2.0
                    lbl_y = (start_y + end_y) / 2.0 - 9.0

                edge_render_data.append({
                    "path_d": path_d,
                    "lbl_x": lbl_x,
                    "lbl_y": lbl_y,
                    "label": disp_label,
                    "full_label": full_label
                })

        # Calculate exact bounding box so no text or arrow is ever clipped
        min_x = min(all_xs) - NODE_RADIUS - 85.0
        max_x = max(all_xs) + NODE_RADIUS + 40.0
        min_y = min_y_bound
        max_y = max_y_bound
        view_w = max(max_x - min_x, 150.0)
        view_h = max(max_y - min_y, 90.0)

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{min_x:.1f} {min_y:.1f} {view_w:.1f} {view_h:.1f}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet" class="automata-svg w-full h-auto select-none font-sans" style="color-scheme: dark; background: transparent; display: block; margin: 0 auto;">',
            '  <defs>',
            '    <filter id="glow-gold-dfa" x="-30%" y="-30%" width="160%" height="160%">',
            '      <feGaussianBlur stdDeviation="4" result="blur" />',
            '      <feComposite in="SourceGraphic" in2="blur" operator="over" />',
            '    </filter>',
            '    <marker id="dfa-arrow-solid" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">',
            '      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#94a3b8" />',
            '    </marker>',
            '    <marker id="dfa-arrow-start" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">',
            '      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#38bdf8" />',
            '    </marker>',
            '  </defs>',
            '  <g id="dfa-scene">'
        ]

        # 4. Render Edges
        for ed in edge_render_data:
            svg_parts.append(
                f'    <path d="{ed["path_d"]}" fill="none" stroke="#94a3b8" stroke-width="1.8" marker-end="url(#dfa-arrow-solid)" />'
            )
            lbl_w = max(16.0, len(ed["label"]) * 7.5 + 8.0)
            svg_parts.append(
                f'    <rect x="{ed["lbl_x"] - lbl_w/2:.1f}" y="{ed["lbl_y"] - 8:.1f}" width="{lbl_w:.1f}" height="15" rx="3" fill="#090d16" fill-opacity="0.88" />'
            )
            title_tag = f'<title>Transition on: {_escape_xml(ed["full_label"])}</title>'
            svg_parts.append(
                f'    <text x="{ed["lbl_x"]:.1f}" y="{ed["lbl_y"] + 3.5:.1f}" text-anchor="middle" fill="#38bdf8" font-size="11" font-weight="600" font-family="system-ui, sans-serif">{title_tag}{_escape_xml(ed["label"])}</text>'
            )

        # 5. Start indicator
        sx, sy = node_pos[start_id]
        svg_parts.append(
            f'    <line x1="{sx - NODE_RADIUS - 40:.1f}" y1="{sy:.1f}" x2="{sx - NODE_RADIUS - 4:.1f}" y2="{sy:.1f}" stroke="#38bdf8" stroke-width="2.0" marker-end="url(#dfa-arrow-start)" />'
        )
        svg_parts.append(
            f'    <text x="{sx - NODE_RADIUS - 46:.1f}" y="{sy + 4:.1f}" text-anchor="end" fill="#38bdf8" font-size="11" font-weight="700" letter-spacing="0.04em" font-family="system-ui, sans-serif">START</text>'
        )

        # 6. Render DFA states
        for sid, (x, y) in node_pos.items():
            state = dfa.states[sid]
            is_st_start = state.is_start
            is_st_accept = state.is_accept
            is_active = (sid == highlighted_state)

            if is_active:
                fill_color = "#78350f"
                border_color = "#fbbf24"
                text_color = "#fef08a"
                stroke_w = 2.5
                filter_attr = ' filter="url(#glow-gold-dfa)"'
            elif is_st_accept:
                fill_color = "#064e3b"
                border_color = "#22c55e"
                text_color = "#86efac"
                stroke_w = 2.0
                filter_attr = ''
            elif is_st_start:
                fill_color = "#1e3a8a"
                border_color = "#38bdf8"
                text_color = "#ffffff"
                stroke_w = 2.0
                filter_attr = ''
            else:
                fill_color = "#1e293b"
                border_color = "#475569"
                text_color = "#f8fafc"
                stroke_w = 1.6
                filter_attr = ''

            tooltip = f"DFA State D{sid}: {state.nfa_set_str}"
            svg_parts.append(
                f'    <g id="dfa-group-D{sid}" class="cursor-pointer" data-dfa-state-id="{sid}" data-nfa-subset="{state.nfa_set_str}">'
            )
            svg_parts.append(
                f'      <circle id="dfa-node-D{sid}" cx="{x:.1f}" cy="{y:.1f}" r="{NODE_RADIUS}" fill="{fill_color}" stroke="{border_color}" stroke-width="{stroke_w}"{filter_attr}><title>{tooltip}</title></circle>'
            )
            if is_st_accept:
                svg_parts.append(
                    f'      <circle id="dfa-inner-D{sid}" cx="{x:.1f}" cy="{y:.1f}" r="{NODE_RADIUS - 4}" fill="none" stroke="#22c55e" stroke-width="1.4" />'
                )

            svg_parts.append(
                f'      <text x="{x:.1f}" y="{y + 4.5:.1f}" text-anchor="middle" fill="{text_color}" font-size="13" font-weight="600" font-family="system-ui, sans-serif">D{sid}</text>'
            )
            svg_parts.append('    </g>')

        svg_parts.append('  </g>')
        svg_parts.append('</svg>')

        return "\n".join(svg_parts)

    @staticmethod
    def export_latex_tikz(dfa: Any, caption: str = "Minimal DFA") -> str:
        """
        Generates publication-ready LaTeX TikZ code for IEEE/ACM/LNCS paper figures.
        Compatible with the standard 'automata' and 'arrows.meta' TikZ packages.
        """
        sids = sorted(dfa.states.keys()) if hasattr(dfa, 'states') and isinstance(dfa.states, dict) else []
        lines = [
            "% Generated by FINIX — Regular Expression Automata Engine",
            "\\documentclass[tikz,border=10pt]{standalone}",
            "\\usetikzlibrary{automata, positioning, arrows.meta}",
            "\\begin{document}",
            "\\begin{tikzpicture}[->, >=Stealth, node distance=2.6cm, semithick]",
        ]
        for idx, sid in enumerate(sids):
            st = dfa.states[sid]
            flags = []
            if getattr(st, 'is_start', False):
                flags.append("initial")
            if getattr(st, 'is_accept', False):
                flags.append("accepting")
            flag_str = (", " + ", ".join(flags)) if flags else ""
            pos_str = "" if idx == 0 else f"[right of=M{sids[idx - 1]}]"
            lines.append(f"  \\node[state{flag_str}] (M{sid}) {pos_str} {{$M_{{{sid}}}$}};")

        lines.append("  \\path")
        edges = []
        for sid in sids:
            st = dfa.states[sid]
            transitions = getattr(st, 'transitions', {})
            for sym, tgt in transitions.items():
                opt = "[loop above]" if sid == tgt else ("[bend left=25]" if sid > tgt else "")
                edges.append(f"    (M{sid}) edge {opt} node {{\\ttfamily {sym}}} (M{tgt})")
        if edges:
            lines.append("\n".join(edges) + ";")
        lines.append("\\end{tikzpicture}")
        lines.append("\\end{document}")
        return "\n".join(lines)
