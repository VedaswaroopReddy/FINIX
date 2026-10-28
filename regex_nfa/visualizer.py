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
        matching the clean textbook aesthetic of FINIX(1).
        - Start state: soft indigo (#e0e7ff) with indigo border (#4338ca) and 'start' indicator
        - Normal states: clean off-white (#f8fafc) with slate border (#334155)
        - Accept state: soft mint (#dcfce7) with emerald border (#15803d) and double circle
        - Edges: solid slate (#475569) for symbols, dashed grey (#94a3b8) for ε-transitions
        - White label pills with high contrast slate typography
        """
        import math
        highlighted = highlighted_states or set()

        # 1. Assign columns via BFS distance from the start state
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

        # 3. Geometric layout constants (matching textbook-grade layered standards)
        NODE_RADIUS = 24
        COLUMN_GAP = 125
        ROW_GAP = 90
        PADDING_X = 90
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
        for (u, v), sym_labels in pair_edges.items():
            ux, uy, u_col = node_pos[u]
            vx, vy, v_col = node_pos[v]

            is_eps = (sym_labels == [EPSILON])
            edge_color = "#c084fc" if is_eps else "#94a3b8"
            marker_id = "arrow-eps" if is_eps else "arrow-solid"
            dash_style = ' stroke-dasharray="5 3"' if is_eps else ''
            label_text = ", ".join(sym_labels)

            is_backward = (v_col <= u_col)
            span = abs(v_col - u_col)
            dx = vx - ux
            dy = vy - uy
            needs_curve = is_backward or span > 1

            if not needs_curve:
                # Direct straight forward edge
                x1, y1 = point_towards(ux, uy, vx, vy, NODE_RADIUS)
                x2, y2 = point_towards(vx, vy, ux, uy, NODE_RADIUS + 4)
                path_d = f"M {x1:.1f} {y1:.1f} L {x2:.1f} {y2:.1f}"
                lbl_x = (x1 + x2) / 2.0
                lbl_y = (y1 + y2) / 2.0 - 9
            else:
                # Quadratic curve: backward edges bow downward (+), forward bypasses bow upward (-)
                bow = (1 if is_backward else -1) * (38 + span * 15)
                mid_x = (ux + vx) / 2.0
                mid_y = (uy + vy) / 2.0
                is_vertical = abs(dx) < 1.0
                cx = mid_x + abs(bow) if is_vertical else mid_x
                cy = mid_y if is_vertical else mid_y + bow
                min_y_bound = min(min_y_bound, cy - 25)
                max_y_bound = max(max_y_bound, cy + 25)

                x1, y1 = point_towards(ux, uy, cx, cy, NODE_RADIUS)
                x2, y2 = point_towards(vx, vy, cx, cy, NODE_RADIUS + 4)
                path_d = f"M {x1:.1f} {y1:.1f} Q {cx:.1f} {cy:.1f} {x2:.1f} {y2:.1f}"
                lbl_x = 0.25 * x1 + 0.5 * cx + 0.25 * x2
                lbl_y = (0.25 * y1 + 0.5 * cy + 0.25 * y2) + (13 if cy > mid_y else -9)

            edge_render_data.append({
                "path_d": path_d,
                "edge_color": edge_color,
                "dash_style": dash_style,
                "marker_id": marker_id,
                "lbl_x": lbl_x,
                "lbl_y": lbl_y,
                "label_text": label_text,
                "is_eps": is_eps
            })

        # Calculate exact bounding box so no text or arrow is ever clipped
        all_xs = [pos[0] for pos in node_pos.values()]
        all_ys = [pos[1] for pos in node_pos.values()]
        min_x = min(all_xs) - NODE_RADIUS - 85.0
        max_x = max(all_xs) + NODE_RADIUS + 40.0
        min_y = min(min_y_bound, min(all_ys) - NODE_RADIUS - 30.0)
        max_y = max(max_y_bound, max(all_ys) + NODE_RADIUS + 30.0)
        view_w = max(max_x - min_x, 140.0)
        view_h = max(max_y - min_y, 90.0)

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{min_x:.1f} {min_y:.1f} {view_w:.1f} {view_h:.1f}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet" class="nfa-layered-svg mx-auto block" role="img" aria-label="Generated ε-NFA" style="background: transparent; display: block; margin: 0 auto;">',
            '  <defs>',
            '    <filter id="glow-gold" x="-30%" y="-30%" width="160%" height="160%">',
            '      <feGaussianBlur stdDeviation="4" result="blur" />',
            '      <feComposite in="SourceGraphic" in2="blur" operator="over" />',
            '    </filter>',
            '    <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">',
            '      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#94a3b8" />',
            '    </marker>',
            '    <marker id="arrow-solid" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">',
            '      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#94a3b8" />',
            '    </marker>',
            '    <marker id="arrow-eps" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">',
            '      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#c084fc" />',
            '    </marker>',
            '    <marker id="arrow-start" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="9" markerHeight="9" orient="auto-start-reverse">',
            '      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#38bdf8" />',
            '    </marker>',
            '  </defs>',
            '  <g class="edges">'
        ]

        # 5. Render edges
        for ed in edge_render_data:
            svg_parts.append(
                f'    <path d="{ed["path_d"]}" fill="none" stroke="{ed["edge_color"]}" stroke-width="2.2"{ed["dash_style"]} marker-end="url(#{ed["marker_id"]})" />'
            )
            pill_w = max(20.0, len(ed["label_text"]) * 8.5 + 10.0)
            pill_border = "#c084fc" if ed["is_eps"] else "#38bdf8"
            svg_parts.append(
                f'    <rect x="{ed["lbl_x"] - pill_w/2:.1f}" y="{ed["lbl_y"] - 10:.1f}" width="{pill_w:.1f}" height="17" rx="4" fill="#131b2e" stroke="{pill_border}" stroke-width="1.2" />'
            )
            font_style = 'italic' if ed["is_eps"] else 'normal'
            font_weight = '700'
            text_color = '#e9d5ff' if ed["is_eps"] else '#38bdf8'
            svg_parts.append(
                f'    <text x="{ed["lbl_x"]:.1f}" y="{ed["lbl_y"] + 3:.1f}" text-anchor="middle" fill="{text_color}" font-style="{font_style}" font-weight="{font_weight}" font-size="12" font-family="ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace">{ed["label_text"]}</text>'
            )

        svg_parts.append('  </g>')
        svg_parts.append('  <g class="nodes">')

        # 6. Start indicator arrow into q0 with no overlap
        sx, sy, _ = node_pos[nfa.start_state]
        svg_parts.append(
            f'    <line x1="{sx - NODE_RADIUS - 44:.1f}" y1="{sy:.1f}" x2="{sx - NODE_RADIUS - 4:.1f}" y2="{sy:.1f}" stroke="#38bdf8" stroke-width="2.2" marker-end="url(#arrow-start)" />'
        )
        svg_parts.append(
            f'    <text x="{sx - NODE_RADIUS - 50:.1f}" y="{sy + 4:.1f}" text-anchor="end" fill="#38bdf8" font-size="12" font-weight="700" font-family="system-ui, -apple-system, BlinkMacSystemFont, sans-serif">start</text>'
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
                stroke_w = 3.0
                filter_attr = ' filter="url(#glow-gold)"'
            elif is_st_accept:
                fill_color = "#064e3b"
                border_color = "#22c55e"
                text_color = "#86efac"
                stroke_w = 2.5
                filter_attr = ''
            elif is_st_start:
                fill_color = "#1e3a8a"
                border_color = "#38bdf8"
                text_color = "#ffffff"
                stroke_w = 2.5
                filter_attr = ''
            else:
                fill_color = "#1e293b"
                border_color = "#64748b"
                text_color = "#f8fafc"
                stroke_w = 2.0
                filter_attr = ''

            svg_parts.append(
                f'    <circle id="node-q{st.id}" data-state-id="{st.id}" data-is-start="{str(is_st_start).lower()}" data-is-accept="{str(is_st_accept).lower()}" cx="{x:.1f}" cy="{y:.1f}" r="{NODE_RADIUS}" fill="{fill_color}" stroke="{border_color}" stroke-width="{stroke_w}"{filter_attr} />'
            )
            if is_st_accept:
                svg_parts.append(
                    f'    <circle id="inner-q{st.id}" data-state-id="{st.id}" cx="{x:.1f}" cy="{y:.1f}" r="{NODE_RADIUS - 4}" fill="none" stroke="#4ade80" stroke-width="1.8" />'
                )

            svg_parts.append(
                f'    <text x="{x:.1f}" y="{y + 4.5:.1f}" text-anchor="middle" fill="{text_color}" font-size="13" font-weight="700" font-family="ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace">q{st.id}</text>'
            )

        svg_parts.append('  </g>')
        svg_parts.append('</svg>')

        return "\n".join(svg_parts)

    @staticmethod
    def generate_dfa_layered_svg(dfa: Any, highlighted_state: Optional[int] = None) -> str:
        """
        Generates a publication-grade SVG diagram of the Deterministic Finite Automaton (DFA).
        Displays canonical macro-state names (D0, D1, ...) alongside constituent NFA subsets ({q0, q1, ...}).
        """
        import math

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
        NODE_RADIUS = 28
        COLUMN_GAP = 145
        ROW_GAP = 100
        PADDING_X = 90
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

        # Check self-loops and back-edges to expand viewbox if needed
        has_self_loops = any(
            t["from"] == t["to"] for t in dfa.get_grouped_transitions()
        )
        has_back_edges = any(
            column.get(int(t["to"].replace("D", "")), 0) < column.get(int(t["from"].replace("D", "")), 0)
            for t in dfa.get_grouped_transitions() if t["from"] != t["to"]
        )

        # Calculate exact bounding box so no text or arrow is ever clipped
        all_xs = [pos[0] for pos in node_pos.values()]
        all_ys = [pos[1] for pos in node_pos.values()]
        min_x = min(all_xs) - NODE_RADIUS - 85.0
        max_x = max(all_xs) + NODE_RADIUS + 40.0
        min_y = min(all_ys) - NODE_RADIUS - (55.0 if has_self_loops else 30.0)
        max_y = max(all_ys) + NODE_RADIUS + (75.0 if has_back_edges else 30.0)
        view_w = max(max_x - min_x, 150.0)
        view_h = max(max_y - min_y, 90.0)

        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{min_x:.1f} {min_y:.1f} {view_w:.1f} {view_h:.1f}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet" class="w-full h-auto select-none font-sans" style="background: transparent; display: block; margin: 0 auto;">',
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
        grouped_edges = dfa.get_grouped_transitions()
        for edge in grouped_edges:
            src_id = int(edge["from"].replace("D", ""))
            tgt_id = int(edge["to"].replace("D", ""))
            label = edge["label"]

            if src_id not in node_pos or tgt_id not in node_pos:
                continue

            x1, y1 = node_pos[src_id]
            x2, y2 = node_pos[tgt_id]

            if src_id == tgt_id:
                # Self Loop arc
                loop_r = 22
                top_y = y1 - NODE_RADIUS
                p1_x = x1 - 12
                p2_x = x1 + 12
                path_d = f"M {p1_x:.1f} {top_y:.1f} C {x1 - 32:.1f} {top_y - loop_r * 2:.1f}, {x1 + 32:.1f} {top_y - loop_r * 2:.1f}, {p2_x:.1f} {top_y:.1f}"
                svg_parts.append(
                    f'    <path d="{path_d}" fill="none" stroke="#94a3b8" stroke-width="2.2" marker-end="url(#dfa-arrow-solid)" />'
                )
                lbl_len = max(len(label) * 8.0 + 12.0, 22.0)
                lbl_x = x1
                lbl_y = top_y - loop_r * 2 + 3
                svg_parts.append(
                    f'    <rect x="{lbl_x - lbl_len/2:.1f}" y="{lbl_y - 9:.1f}" width="{lbl_len:.1f}" height="17" rx="4" fill="#131b2e" stroke="#38bdf8" stroke-width="1.2" />'
                )
                svg_parts.append(
                    f'    <text x="{lbl_x:.1f}" y="{lbl_y + 4:.1f}" text-anchor="middle" fill="#38bdf8" font-size="12" font-weight="700" font-family="ui-monospace, monospace">{label}</text>'
                )
            else:
                c1 = column.get(src_id, 0)
                c2 = column.get(tgt_id, 0)
                is_back = (c2 <= c1)

                dx = x2 - x1
                dy = y2 - y1
                dist = math.hypot(dx, dy)
                if dist < 1e-4:
                    continue

                if is_back:
                    # Curved arc beneath nodes
                    col_diff = abs(c1 - c2)
                    sag = 48 + col_diff * 18
                    mid_x = (x1 + x2) / 2.0
                    mid_y = max(y1, y2) + sag
                    ctrl_x = mid_x
                    ctrl_y = mid_y

                    # Quadratic Bezier trimmed to perimeter
                    ctrl_dx = ctrl_x - x1
                    ctrl_dy = ctrl_y - y1
                    ctrl_dist = math.hypot(ctrl_dx, ctrl_dy)
                    start_x = x1 + (ctrl_dx / ctrl_dist) * NODE_RADIUS
                    start_y = y1 + (ctrl_dy / ctrl_dist) * NODE_RADIUS

                    end_dx = ctrl_x - x2
                    end_dy = ctrl_y - y2
                    end_dist = math.hypot(end_dx, end_dy)
                    end_x = x2 + (end_dx / end_dist) * (NODE_RADIUS + 3.0)
                    end_y = y2 + (end_dy / end_dist) * (NODE_RADIUS + 3.0)

                    path_d = f"M {start_x:.1f} {start_y:.1f} Q {ctrl_x:.1f} {ctrl_y:.1f} {end_x:.1f} {end_y:.1f}"
                    lbl_x = (start_x + 2 * ctrl_x + end_x) / 4.0
                    lbl_y = (start_y + 2 * ctrl_y + end_y) / 4.0
                else:
                    # Straight or slight forward curve
                    ux = dx / dist
                    uy = dy / dist
                    start_x = x1 + ux * NODE_RADIUS
                    start_y = y1 + uy * NODE_RADIUS
                    end_x = x2 - ux * (NODE_RADIUS + 3.0)
                    end_y = y2 - uy * (NODE_RADIUS + 3.0)

                    if abs(c2 - c1) > 1 and abs(dy) < 10:
                        # Arc over intermediate columns
                        ctrl_x = (x1 + x2) / 2.0
                        ctrl_y = y1 - 34
                        path_d = f"M {start_x:.1f} {start_y:.1f} Q {ctrl_x:.1f} {ctrl_y:.1f} {end_x:.1f} {end_y:.1f}"
                        lbl_x = ctrl_x
                        lbl_y = ctrl_y + 8
                    else:
                        path_d = f"M {start_x:.1f} {start_y:.1f} L {end_x:.1f} {end_y:.1f}"
                        lbl_x = (start_x + end_x) / 2.0
                        lbl_y = (start_y + end_y) / 2.0 - 9

                svg_parts.append(
                    f'    <path d="{path_d}" fill="none" stroke="#94a3b8" stroke-width="2.2" marker-end="url(#dfa-arrow-solid)" />'
                )
                lbl_len = max(len(label) * 8.0 + 12.0, 22.0)
                svg_parts.append(
                    f'    <rect x="{lbl_x - lbl_len/2:.1f}" y="{lbl_y - 9:.1f}" width="{lbl_len:.1f}" height="17" rx="4" fill="#131b2e" stroke="#38bdf8" stroke-width="1.2" />'
                )
                svg_parts.append(
                    f'    <text x="{lbl_x:.1f}" y="{lbl_y + 4:.1f}" text-anchor="middle" fill="#38bdf8" font-size="12" font-weight="700" font-family="ui-monospace, monospace">{label}</text>'
                )

        # 5. Start indicator
        sx, sy = node_pos[start_id]
        svg_parts.append(
            f'    <line x1="{sx - NODE_RADIUS - 44:.1f}" y1="{sy:.1f}" x2="{sx - NODE_RADIUS - 4:.1f}" y2="{sy:.1f}" stroke="#38bdf8" stroke-width="2.2" marker-end="url(#dfa-arrow-start)" />'
        )
        svg_parts.append(
            f'    <text x="{sx - NODE_RADIUS - 50:.1f}" y="{sy + 4.5:.1f}" text-anchor="end" fill="#38bdf8" font-size="12" font-weight="700">start</text>'
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
                sub_color = "#fef9c3"
                stroke_w = 3.0
                filter_attr = ' filter="url(#glow-gold-dfa)"'
            elif is_st_accept:
                fill_color = "#064e3b"
                border_color = "#22c55e"
                text_color = "#86efac"
                sub_color = "#bbf7d0"
                stroke_w = 2.5
                filter_attr = ''
            elif is_st_start:
                fill_color = "#1e3a8a"
                border_color = "#38bdf8"
                text_color = "#ffffff"
                sub_color = "#93c5fd"
                stroke_w = 2.5
                filter_attr = ''
            else:
                fill_color = "#1e293b"
                border_color = "#64748b"
                text_color = "#f8fafc"
                sub_color = "#94a3b8"
                stroke_w = 2.0
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
                    f'      <circle id="dfa-inner-D{sid}" cx="{x:.1f}" cy="{y:.1f}" r="{NODE_RADIUS - 4}" fill="none" stroke="#4ade80" stroke-width="1.8" />'
                )

            svg_parts.append(
                f'      <text x="{x:.1f}" y="{y - 2:.1f}" text-anchor="middle" fill="{text_color}" font-size="13" font-weight="700" font-family="ui-monospace, monospace">D{sid}</text>'
            )
            # Small constituent NFA count / sublabel
            sub_lbl = f"{len(state.nfa_states)} q"
            svg_parts.append(
                f'      <text x="{x:.1f}" y="{y + 12:.1f}" text-anchor="middle" fill="{sub_color}" font-size="10" font-weight="600">{sub_lbl}</text>'
            )
            svg_parts.append('    </g>')

        svg_parts.append('  </g>')
        svg_parts.append('</svg>')

        return "\n".join(svg_parts)
