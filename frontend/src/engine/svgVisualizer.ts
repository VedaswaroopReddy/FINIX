/**
 * svgVisualizer.ts: FINIX Ω Publication-Grade Vector Diagram Engine & Academic Exporter.
 * Renders AST Trees, Thompson ε-NFAs, Rabin-Scott Powerset DFAs, and Hopcroft Minimal DFAs,
 * plus exports Graphviz DOT, LaTeX TikZ, and Formal TOC ASCII Transition Tables.
 */

import {
  ASTNode,
  CompiledDFA,
  CompiledNFA,
  DualSimulationResult,
  EPSILON,
} from './automataEngine';

function escapeXml(unsafe: string): string {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function pointTowards(
  x1: number,
  y1: number,
  x2: number,
  y2: number,
  dist: number
): [number, number] {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const d = Math.hypot(dx, dy) || 1.0;
  return [x1 + (dx / d) * dist, y1 + (dy / d) * dist];
}

// ============================================================================
// 1. Abstract Syntax Tree (AST) Hierarchical SVG Renderer
// ============================================================================

export function generateAstSvg(root: ASTNode): string {
  interface LayoutNode {
    node: ASTNode;
    x: number;
    y: number;
    width: number;
    children: LayoutNode[];
  }

  const LEVEL_HEIGHT = 76;
  const LEAF_WIDTH = 86;
  const NODE_RADIUS = 22;

  function measure(n: ASTNode): LayoutNode {
    if (n.children.length === 0) {
      return { node: n, x: 0, y: 0, width: LEAF_WIDTH, children: [] };
    }
    const chLayouts = n.children.map(measure);
    const totalW = Math.max(
      LEAF_WIDTH,
      chLayouts.reduce((acc, c) => acc + c.width, 0)
    );
    return { node: n, x: 0, y: 0, width: totalW, children: chLayouts };
  }

  const rootLayout = measure(root);

  let maxDepth = 0;
  const allNodes: LayoutNode[] = [];

  function assignCoords(ln: LayoutNode, left: number, depth: number) {
    if (depth > maxDepth) maxDepth = depth;
    ln.x = left + ln.width / 2;
    ln.y = 48 + depth * LEVEL_HEIGHT;
    allNodes.push(ln);

    let cursor = left;
    for (const ch of ln.children) {
      assignCoords(ch, cursor, depth + 1);
      cursor += ch.width;
    }
  }

  assignCoords(rootLayout, 24, 0);

  const viewW = Math.max(360, rootLayout.width + 48);
  const viewH = Math.max(180, (maxDepth + 1) * LEVEL_HEIGHT + 44);

  const parts: string[] = [
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewW.toFixed(1)} ${viewH.toFixed(1)}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet" class="automata-svg select-none">`,
    `  <g class="ast-edges">`,
  ];

  for (const ln of allNodes) {
    for (const ch of ln.children) {
      const [x1, y1] = pointTowards(ln.x, ln.y, ch.x, ch.y, NODE_RADIUS);
      const [x2, y2] = pointTowards(ch.x, ch.y, ln.x, ln.y, NODE_RADIUS);
      parts.push(
        `    <path d="M ${x1.toFixed(1)} ${y1.toFixed(1)} C ${x1.toFixed(1)} ${((y1 + y2) / 2).toFixed(1)}, ${x2.toFixed(1)} ${((y1 + y2) / 2).toFixed(1)}, ${x2.toFixed(1)} ${y2.toFixed(1)}" fill="none" stroke="#475569" stroke-width="1.8" />`
      );
    }
  }

  parts.push(`  </g>`);
  parts.push(`  <g class="ast-nodes">`);

  for (const ln of allNodes) {
    const isLeaf = ln.children.length === 0;
    const isOperator = !isLeaf;
    const fill = isOperator ? '#1e293b' : '#0c4a6e';
    const stroke = isOperator ? '#c084fc' : '#38bdf8';
    const textColor = isOperator ? '#f3e8ff' : '#e0f2fe';

    const rawLabel = ln.node.label.split(' ')[0];
    const dispLabel = rawLabel.length > 7 ? rawLabel.slice(0, 6) + '…' : rawLabel;

    parts.push(
      `    <g transform="translate(${ln.x.toFixed(1)}, ${ln.y.toFixed(1)})">`,
      `      <circle r="${NODE_RADIUS}" fill="${fill}" stroke="${stroke}" stroke-width="1.8" />`,
      `      <text y="4" text-anchor="middle" fill="${textColor}" font-size="11.5" font-weight="600" font-family="'JetBrains Mono', monospace">${escapeXml(dispLabel)}</text>`,
      `      <text y="${NODE_RADIUS + 13}" text-anchor="middle" fill="#94a3b8" font-size="9.5" font-family="'Plus Jakarta Sans', sans-serif">${escapeXml(ln.node.kind)}</text>`,
      `    </g>`
    );
  }

  parts.push(`  </g>`);
  parts.push(`</svg>`);
  return parts.join('\n');
}

// ============================================================================
// 2. Thompson ε-NFA Layered Sugiyama SVG Renderer
// ============================================================================

export interface NFAHighlightConfig {
  activeStateIds?: Set<number>;
  directMoveIds?: Set<number>;
  epsilonAddedIds?: Set<number>;
}

export function generateNfaSvg(nfa: CompiledNFA, highlights: NFAHighlightConfig = {}): string {
  const activeSet = highlights.activeStateIds ?? new Set<number>();
  const directSet = highlights.directMoveIds ?? new Set<number>();
  const epsSet = highlights.epsilonAddedIds ?? new Set<number>();

  // 1. Assign columns via BFS shortest distance from startStateId
  const column = new Map<number, number>([[nfa.startStateId, 0]]);
  const queue: number[] = [nfa.startStateId];

  while (queue.length > 0) {
    const curr = queue.shift()!;
    const c = column.get(curr)!;
    const st = nfa.states.get(curr);
    if (!st) continue;
    for (const tr of st.transitions) {
      if (!column.has(tr.targetId)) {
        column.set(tr.targetId, c + 1);
        queue.push(tr.targetId);
      }
    }
  }

  for (const sid of nfa.states.keys()) {
    if (!column.has(sid)) column.set(sid, 0);
  }

  const maxCol = Math.max(0, ...Array.from(column.values()));
  const cols: number[][] = Array.from({ length: maxCol + 1 }, () => []);
  for (const sid of Array.from(nfa.states.keys()).sort((a, b) => a - b)) {
    cols[column.get(sid)!].push(sid);
  }

  // 2. Two-pass Barycenter heuristic to minimize edge crossings
  const rowIdx = new Map<number, number>();
  cols.forEach((colStates, cIdx) => {
    if (cIdx > 0) {
      const getBarycenter = (sid: number) => {
        const preds: number[] = [];
        for (const [pId, pSt] of nfa.states.entries()) {
          if (
            column.get(pId) === cIdx - 1 &&
            pSt.transitions.some((tr) => tr.targetId === sid)
          ) {
            preds.push(rowIdx.get(pId) ?? 0);
          }
        }
        if (preds.length === 0) return sid;
        return preds.reduce((a, b) => a + b, 0) / preds.length;
      };
      colStates.sort((a, b) => getBarycenter(a) - getBarycenter(b) || a - b);
    }
    colStates.forEach((sid, rIdx) => rowIdx.set(sid, rIdx));
  });

  // 2. Adaptive Sub-column folding for wide/deep layers to prevent vertical needle squishing
  const rawMaxRows = Math.max(1, ...cols.map((c) => c.length));
  const MAX_PER_SUBCOL = rawMaxRows > 7 ? 6 : Math.max(rawMaxRows, 1);

  const stateEffectiveCol = new Map<number, number>();
  const stateEffectiveRow = new Map<number, number>();
  let currentBaseCol = 0;

  cols.forEach((colStates) => {
    const subColsNeeded = Math.max(1, Math.ceil(colStates.length / MAX_PER_SUBCOL));
    colStates.forEach((sid, rIdx) => {
      const subCol = Math.floor(rIdx / MAX_PER_SUBCOL);
      const subRow = rIdx % MAX_PER_SUBCOL;
      stateEffectiveCol.set(sid, currentBaseCol + subCol);
      stateEffectiveRow.set(sid, subRow);
    });
    currentBaseCol += subColsNeeded;
  });

  const effectiveMaxRows = Math.min(rawMaxRows, MAX_PER_SUBCOL);

  const NODE_RADIUS = nfa.states.size > 30 ? 18 : 22;
  const COLUMN_GAP = nfa.states.size > 30 ? 96 : 108;
  const ROW_GAP = nfa.states.size > 30 ? 66 : 78;
  const PADDING_X = 76;
  const PADDING_Y = 58;

  const height = PADDING_Y * 2 + Math.max(1, effectiveMaxRows - 1) * ROW_GAP + NODE_RADIUS * 2;

  const nodePos = new Map<number, { x: number; y: number; col: number }>();
  for (const sid of nfa.states.keys()) {
    const effCol = stateEffectiveCol.get(sid) ?? 0;
    const effRow = stateEffectiveRow.get(sid) ?? 0;
    nodePos.set(sid, {
      x: PADDING_X + NODE_RADIUS + effCol * COLUMN_GAP,
      y: PADDING_Y + NODE_RADIUS + effRow * ROW_GAP,
      col: effCol,
    });
  }

  const allYs = Array.from(nodePos.values()).map((p) => p.y);
  const allXs = Array.from(nodePos.values()).map((p) => p.x);
  const minGraphY = Math.min(...allYs);
  const maxGraphY = Math.max(...allYs);
  const midGraphY = (minGraphY + maxGraphY) / 2;

  // Group parallel edges between same (u, v)
  const pairEdges = new Map<string, { u: number; v: number; labels: string[] }>();
  for (const [u, st] of nfa.states.entries()) {
    for (const tr of st.transitions) {
      const key = `${u}->${tr.targetId}`;
      if (!pairEdges.has(key)) {
        pairEdges.set(key, { u, v: tr.targetId, labels: [] });
      }
      const entry = pairEdges.get(key)!;
      if (!entry.labels.includes(tr.display)) {
        entry.labels.push(tr.display);
      }
    }
  }

  let minYBound = minGraphY - NODE_RADIUS - 32;
  let maxYBound = maxGraphY + NODE_RADIUS + 32;

  interface EdgeRender {
    pathD: string;
    edgeColor: string;
    dashStyle: string;
    markerId: string;
    lblX: number;
    lblY: number;
    labelText: string;
    isEps: boolean;
  }

  const edgeRenders: EdgeRender[] = [];
  let backEdgeCounter = 0;

  for (const { u, v, labels } of pairEdges.values()) {
    const uPos = nodePos.get(u)!;
    const vPos = nodePos.get(v)!;
    const isEps = labels.length === 1 && labels[0] === EPSILON;
    const edgeColor = isEps ? '#c084fc' : '#94a3b8';
    const markerId = isEps ? 'nfa-arrow-eps' : 'nfa-arrow-solid';
    const dashStyle = isEps ? ' stroke-dasharray="4 3"' : '';
    const labelText = labels.join(', ');

    if (u === v) {
      const topY = uPos.y - NODE_RADIUS;
      const loopR = 22;
      const pathD = `M ${(uPos.x - 12).toFixed(1)} ${topY.toFixed(1)} C ${(uPos.x - 32).toFixed(1)} ${(topY - loopR * 2.1).toFixed(1)}, ${(uPos.x + 32).toFixed(1)} ${(topY - loopR * 2.1).toFixed(1)}, ${(uPos.x + 12).toFixed(1)} ${topY.toFixed(1)}`;
      const lblY = topY - loopR * 1.9;
      minYBound = Math.min(minYBound, lblY - 16);
      edgeRenders.push({
        pathD,
        edgeColor,
        dashStyle,
        markerId,
        lblX: uPos.x,
        lblY,
        labelText,
        isEps,
      });
      continue;
    }

    const isBackward = vPos.col <= uPos.col;
    const span = Math.abs(vPos.col - uPos.col);

    if (!isBackward && span === 1) {
      const [x1, y1] = pointTowards(uPos.x, uPos.y, vPos.x, vPos.y, NODE_RADIUS);
      const [x2, y2] = pointTowards(vPos.x, vPos.y, uPos.x, uPos.y, NODE_RADIUS + 4);
      edgeRenders.push({
        pathD: `M ${x1.toFixed(1)} ${y1.toFixed(1)} L ${x2.toFixed(1)} ${y2.toFixed(1)}`,
        edgeColor,
        dashStyle,
        markerId,
        lblX: (x1 + x2) / 2,
        lblY: (y1 + y2) / 2 - 8,
        labelText,
        isEps,
      });
    } else if (isBackward) {
      const arcOver = vPos.y <= midGraphY;
      const cx = (uPos.x + vPos.x) / 2;
      const stagger = (backEdgeCounter++ % 2) * 14;
      const cy = arcOver
        ? minGraphY - NODE_RADIUS - 34 - span * 11 - stagger
        : maxGraphY + NODE_RADIUS + 34 + span * 11 + stagger;

      minYBound = Math.min(minYBound, cy - 26);
      maxYBound = Math.max(maxYBound, cy + 26);

      const [x1, y1] = pointTowards(uPos.x, uPos.y, cx, cy, NODE_RADIUS);
      const [x2, y2] = pointTowards(vPos.x, vPos.y, cx, cy, NODE_RADIUS + 4);
      edgeRenders.push({
        pathD: `M ${x1.toFixed(1)} ${y1.toFixed(1)} Q ${cx.toFixed(1)} ${cy.toFixed(1)} ${x2.toFixed(1)} ${y2.toFixed(1)}`,
        edgeColor,
        dashStyle,
        markerId,
        lblX: 0.25 * x1 + 0.5 * cx + 0.25 * x2,
        lblY: 0.25 * y1 + 0.5 * cy + 0.25 * y2 + (arcOver ? -8 : 10),
        labelText,
        isEps,
      });
    } else {
      const arcOver = Math.min(uPos.y, vPos.y) <= midGraphY;
      const cx = (uPos.x + vPos.x) / 2;
      const cy = (uPos.y + vPos.y) / 2 + (arcOver ? -1 : 1) * (28 + span * 10);
      minYBound = Math.min(minYBound, cy - 22);
      maxYBound = Math.max(maxYBound, cy + 22);

      const [x1, y1] = pointTowards(uPos.x, uPos.y, cx, cy, NODE_RADIUS);
      const [x2, y2] = pointTowards(vPos.x, vPos.y, cx, cy, NODE_RADIUS + 4);
      edgeRenders.push({
        pathD: `M ${x1.toFixed(1)} ${y1.toFixed(1)} Q ${cx.toFixed(1)} ${cy.toFixed(1)} ${x2.toFixed(1)} ${y2.toFixed(1)}`,
        edgeColor,
        dashStyle,
        markerId,
        lblX: 0.25 * x1 + 0.5 * cx + 0.25 * x2,
        lblY: 0.25 * y1 + 0.5 * cy + 0.25 * y2 + (arcOver ? -8 : 10),
        labelText,
        isEps,
      });
    }
  }

  const minX = Math.min(...allXs) - NODE_RADIUS - 78;
  const maxX = Math.max(...allXs) + NODE_RADIUS + 38;
  const viewW = Math.max(maxX - minX, 160);
  const viewH = Math.max(maxYBound - minYBound, 100);

  const svgParts: string[] = [
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${minX.toFixed(1)} ${minYBound.toFixed(1)} ${viewW.toFixed(1)} ${viewH.toFixed(1)}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet" class="automata-svg select-none">`,
    `  <defs>`,
    `    <filter id="nfa-glow" x="-30%" y="-30%" width="160%" height="160%">`,
    `      <feGaussianBlur stdDeviation="4" result="blur" />`,
    `      <feComposite in="SourceGraphic" in2="blur" operator="over" />`,
    `    </filter>`,
    `    <marker id="nfa-arrow-solid" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">`,
    `      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#94a3b8" />`,
    `    </marker>`,
    `    <marker id="nfa-arrow-eps" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">`,
    `      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#c084fc" />`,
    `    </marker>`,
    `    <marker id="nfa-arrow-start" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">`,
    `      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#38bdf8" />`,
    `    </marker>`,
    `  </defs>`,
    `  <g class="edges">`,
  ];

  for (const ed of edgeRenders) {
    const pillW = Math.max(16, ed.labelText.length * 7.5 + 8);
    const textColor = ed.isEps ? '#c084fc' : '#38bdf8';
    const fontStyle = ed.isEps ? 'italic' : 'normal';
    svgParts.push(
      `    <path d="${ed.pathD}" fill="none" stroke="${ed.edgeColor}" stroke-width="1.8"${ed.dashStyle} marker-end="url(#${ed.markerId})" />`,
      `    <rect x="${(ed.lblX - pillW / 2).toFixed(1)}" y="${(ed.lblY - 8).toFixed(1)}" width="${pillW.toFixed(1)}" height="15" rx="3" fill="#090d16" fill-opacity="0.9" />`,
      `    <text x="${ed.lblX.toFixed(1)}" y="${(ed.lblY + 3.5).toFixed(1)}" text-anchor="middle" fill="${textColor}" font-style="${fontStyle}" font-weight="600" font-size="11" font-family="'JetBrains Mono', monospace">${escapeXml(ed.labelText)}</text>`
    );
  }

  svgParts.push(`  </g>`);
  svgParts.push(`  <g class="nodes">`);

  const startPos = nodePos.get(nfa.startStateId)!;
  svgParts.push(
    `    <line x1="${(startPos.x - NODE_RADIUS - 38).toFixed(1)}" y1="${startPos.y.toFixed(1)}" x2="${(startPos.x - NODE_RADIUS - 4).toFixed(1)}" y2="${startPos.y.toFixed(1)}" stroke="#38bdf8" stroke-width="2.0" marker-end="url(#nfa-arrow-start)" />`,
    `    <text x="${(startPos.x - NODE_RADIUS - 44).toFixed(1)}" y="${(startPos.y + 4).toFixed(1)}" text-anchor="end" fill="#38bdf8" font-size="10.5" font-weight="700" font-family="'JetBrains Mono', monospace">START</text>`
  );

  for (const [sid, pos] of nodePos.entries()) {
    const st = nfa.states.get(sid)!;
    const isDirect = directSet.has(sid);
    const isEpsAdd = epsSet.has(sid);
    const isActive = activeSet.has(sid) || isDirect || isEpsAdd;

    let fillColor = '#1e293b';
    let borderColor = '#475569';
    let textColor = '#f8fafc';
    let strokeW = 1.6;
    let filterAttr = '';

    if (isDirect) {
      fillColor = '#0c4a6e';
      borderColor = '#38bdf8';
      textColor = '#e0f2fe';
      strokeW = 2.5;
      filterAttr = ' filter="url(#nfa-glow)"';
    } else if (isEpsAdd) {
      fillColor = '#4c1d95';
      borderColor = '#c084fc';
      textColor = '#f3e8ff';
      strokeW = 2.5;
      filterAttr = ' filter="url(#nfa-glow)"';
    } else if (isActive) {
      fillColor = '#78350f';
      borderColor = '#fbbf24';
      textColor = '#fef08a';
      strokeW = 2.5;
      filterAttr = ' filter="url(#nfa-glow)"';
    } else if (st.isAccept) {
      fillColor = '#064e3b';
      borderColor = '#22c55e';
      textColor = '#86efac';
      strokeW = 2.0;
    } else if (st.isStart) {
      fillColor = '#1e3a8a';
      borderColor = '#38bdf8';
      textColor = '#ffffff';
      strokeW = 2.0;
    }

    svgParts.push(
      `    <g class="nfa-node-group cursor-pointer" data-nfa-id="${sid}">`,
      `      <circle cx="${pos.x.toFixed(1)}" cy="${pos.y.toFixed(1)}" r="${NODE_RADIUS}" fill="${fillColor}" stroke="${borderColor}" stroke-width="${strokeW}"${filterAttr}>`,
      `        <title>NFA State q${sid}${st.isStart ? ' (Start)' : ''}${st.isAccept ? ' (Accept)' : ''}</title>`,
      `      </circle>`
    );
    if (st.isAccept) {
      svgParts.push(
        `      <circle cx="${pos.x.toFixed(1)}" cy="${pos.y.toFixed(1)}" r="${NODE_RADIUS - 4}" fill="none" stroke="${isActive ? borderColor : '#22c55e'}" stroke-width="1.4" />`
      );
    }
    svgParts.push(
      `      <text x="${pos.x.toFixed(1)}" y="${(pos.y + 4).toFixed(1)}" text-anchor="middle" fill="${textColor}" font-size="12" font-weight="600" font-family="'JetBrains Mono', monospace">q${sid}</text>`,
      `    </g>`
    );
  }

  svgParts.push(`  </g>`);
  svgParts.push(`</svg>`);
  return svgParts.join('\n');
}

// ============================================================================
// 3. Deterministic Finite Automaton (Powerset & Minimal DFA) SVG Renderer
// ============================================================================

export interface DFAHighlightConfig {
  activeStateIds?: Set<number>;
  activeTransition?: { from: number; to: number } | null;
  showSubsets?: boolean;
}

export function generateDfaSvg(dfa: CompiledDFA, highlights: DFAHighlightConfig = {}): string {
  const activeSet = highlights.activeStateIds ?? new Set<number>();
  const activeEdge = highlights.activeTransition ?? null;
  const showSubsets = highlights.showSubsets ?? true;

  const startId = dfa.startStateId;
  const allSids = Array.from(dfa.states.keys()).sort((a, b) => a - b);

  const column = new Map<number, number>([[startId, 0]]);
  const queue: number[] = [startId];

  while (queue.length > 0) {
    const curr = queue.shift()!;
    const c = column.get(curr)!;
    const st = dfa.states.get(curr)!;
    for (const targetId of st.transitions.values()) {
      if (!column.has(targetId)) {
        column.set(targetId, c + 1);
        queue.push(targetId);
      }
    }
  }

  for (const sid of allSids) {
    if (!column.has(sid)) column.set(sid, 0);
  }

  const maxCol = Math.max(0, ...Array.from(column.values()));
  const cols: number[][] = Array.from({ length: maxCol + 1 }, () => []);
  for (const sid of allSids) {
    cols[column.get(sid)!].push(sid);
  }

  const rowIdx = new Map<number, number>();
  cols.forEach((colSids, cIdx) => {
    if (cIdx > 0) {
      const getBary = (sid: number) => {
        const preds = allSids.filter(
          (p) =>
            column.get(p) === cIdx - 1 &&
            Array.from(dfa.states.get(p)!.transitions.values()).includes(sid)
        );
        if (preds.length === 0) return sid;
        return preds.reduce((acc, p) => acc + (rowIdx.get(p) ?? 0), 0) / preds.length;
      };
      colSids.sort((a, b) => getBary(a) - getBary(b) || a - b);
    }
    colSids.forEach((sid, rIdx) => rowIdx.set(sid, rIdx));
  });

  // 2. Adaptive Sub-column folding for wide/deep layers to prevent vertical needle squishing
  const rawMaxRows = Math.max(1, ...cols.map((c) => c.length));
  const MAX_PER_SUBCOL = rawMaxRows > 7 ? 6 : Math.max(rawMaxRows, 1);

  const stateEffectiveCol = new Map<number, number>();
  const stateEffectiveRow = new Map<number, number>();
  let currentBaseCol = 0;

  cols.forEach((colSids) => {
    const subColsNeeded = Math.max(1, Math.ceil(colSids.length / MAX_PER_SUBCOL));
    colSids.forEach((sid, rIdx) => {
      const subCol = Math.floor(rIdx / MAX_PER_SUBCOL);
      const subRow = rIdx % MAX_PER_SUBCOL;
      stateEffectiveCol.set(sid, currentBaseCol + subCol);
      stateEffectiveRow.set(sid, subRow);
    });
    currentBaseCol += subColsNeeded;
  });

  const effectiveMaxRows = Math.min(rawMaxRows, MAX_PER_SUBCOL);

  const NODE_RADIUS = allSids.length > 30 ? 20 : 25;
  const COLUMN_GAP = allSids.length > 30 ? 110 : 128;
  const ROW_GAP = allSids.length > 30 ? 76 : 92;
  const PADDING_X = 84;
  const PADDING_Y = 64;

  const height = PADDING_Y * 2 + Math.max(1, effectiveMaxRows - 1) * ROW_GAP + NODE_RADIUS * 2;

  const nodePos = new Map<number, { x: number; y: number }>();
  allSids.forEach((sid) => {
    const effCol = stateEffectiveCol.get(sid) ?? 0;
    const effRow = stateEffectiveRow.get(sid) ?? 0;
    nodePos.set(sid, {
      x: PADDING_X + effCol * COLUMN_GAP,
      y: PADDING_Y + NODE_RADIUS + effRow * ROW_GAP,
    });
  });

  const allXs = Array.from(nodePos.values()).map((p) => p.x);
  const allYs = Array.from(nodePos.values()).map((p) => p.y);
  let minYBound = Math.min(...allYs) - NODE_RADIUS - 36;
  let maxYBound = Math.max(...allYs) + NODE_RADIUS + 42;

  // Group transitions between same (src, tgt)
  const groupedEdges: { src: number; tgt: number; label: string }[] = [];
  for (const sid of allSids) {
    const st = dfa.states.get(sid)!;
    const byTarget = new Map<number, string[]>();
    for (const [sym, tgt] of st.transitions.entries()) {
      if (!byTarget.has(tgt)) byTarget.set(tgt, []);
      byTarget.get(tgt)!.push(sym);
    }
    for (const [tgt, syms] of byTarget.entries()) {
      groupedEdges.push({ src: sid, tgt, label: syms.join(', ') });
    }
  }

  interface DfaEdgeRender {
    pathD: string;
    lblX: number;
    lblY: number;
    label: string;
    isHighlightedEdge: boolean;
  }

  const edgeRenders: DfaEdgeRender[] = [];
  let backEdgeCounter = 0;

  for (const edge of groupedEdges) {
    const p1 = nodePos.get(edge.src);
    const p2 = nodePos.get(edge.tgt);
    if (!p1 || !p2) continue;

    const isHighlightedEdge =
      activeEdge !== null && activeEdge.from === edge.src && activeEdge.to === edge.tgt;

    if (edge.src === edge.tgt) {
      const loopR = 24;
      const topY = p1.y - NODE_RADIUS;
      const pathD = `M ${(p1.x - 14).toFixed(1)} ${topY.toFixed(1)} C ${(p1.x - 36).toFixed(1)} ${(topY - loopR * 2.2).toFixed(1)}, ${(p1.x + 36).toFixed(1)} ${(topY - loopR * 2.2).toFixed(1)}, ${(p1.x + 14).toFixed(1)} ${topY.toFixed(1)}`;
      const lblY = topY - loopR * 2.1 + 3;
      minYBound = Math.min(minYBound, lblY - 16);
      edgeRenders.push({
        pathD,
        lblX: p1.x,
        lblY,
        label: edge.label,
        isHighlightedEdge,
      });
    } else {
      const c1 = stateEffectiveCol.get(edge.src) ?? 0;
      const c2 = stateEffectiveCol.get(edge.tgt) ?? 0;
      const isBack = c2 <= c1;
      const dx = p2.x - p1.x;
      const dy = p2.y - p1.y;
      const dist = Math.hypot(dx, dy) || 1;

      if (isBack) {
        const colDiff = Math.abs(c1 - c2);
        const sag = 48 + colDiff * 32 + (backEdgeCounter % 2) * 18;
        backEdgeCounter++;

        const ctrlX = (p1.x + p2.x) / 2;
        const ctrlY = Math.max(p1.y, p2.y) + sag;
        maxYBound = Math.max(maxYBound, ctrlY + 36);

        const [startX, startY] = pointTowards(p1.x, p1.y, ctrlX, ctrlY, NODE_RADIUS);
        const [endX, endY] = pointTowards(p2.x, p2.y, ctrlX, ctrlY, NODE_RADIUS + 4);
        const pathD = `M ${startX.toFixed(1)} ${startY.toFixed(1)} Q ${ctrlX.toFixed(1)} ${ctrlY.toFixed(1)} ${endX.toFixed(1)} ${endY.toFixed(1)}`;
        const t = backEdgeCounter % 2 === 1 ? 0.38 : 0.62;
        const lblX = (1 - t) ** 2 * startX + 2 * (1 - t) * t * ctrlX + t ** 2 * endX;
        const lblY = (1 - t) ** 2 * startY + 2 * (1 - t) * t * ctrlY + t ** 2 * endY;

        edgeRenders.push({
          pathD,
          lblX,
          lblY,
          label: edge.label,
          isHighlightedEdge,
        });
      } else {
        const ux = dx / dist;
        const uy = dy / dist;
        const startX = p1.x + ux * NODE_RADIUS;
        const startY = p1.y + uy * NODE_RADIUS;
        const endX = p2.x - ux * (NODE_RADIUS + 4);
        const endY = p2.y - uy * (NODE_RADIUS + 4);

        if (Math.abs(c2 - c1) > 1 && Math.abs(dy) < 12) {
          const ctrlX = (p1.x + p2.x) / 2;
          const ctrlY = p1.y - 42;
          minYBound = Math.min(minYBound, ctrlY - 22);
          edgeRenders.push({
            pathD: `M ${startX.toFixed(1)} ${startY.toFixed(1)} Q ${ctrlX.toFixed(1)} ${ctrlY.toFixed(1)} ${endX.toFixed(1)} ${endY.toFixed(1)}`,
            lblX: ctrlX,
            lblY: ctrlY + 8,
            label: edge.label,
            isHighlightedEdge,
          });
        } else {
          edgeRenders.push({
            pathD: `M ${startX.toFixed(1)} ${startY.toFixed(1)} L ${endX.toFixed(1)} ${endY.toFixed(1)}`,
            lblX: (startX + endX) / 2,
            lblY: (startY + endY) / 2 - 9,
            label: edge.label,
            isHighlightedEdge,
          });
        }
      }
    }
  }

  const minX = Math.min(...allXs) - NODE_RADIUS - 85;
  const maxX = Math.max(...allXs) + NODE_RADIUS + 45;
  const viewW = Math.max(maxX - minX, 160);
  const viewH = Math.max(maxYBound - minYBound, 100);

  const svgParts: string[] = [
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${minX.toFixed(1)} ${minYBound.toFixed(1)} ${viewW.toFixed(1)} ${viewH.toFixed(1)}" width="100%" height="100%" preserveAspectRatio="xMidYMid meet" class="automata-svg select-none">`,
    `  <defs>`,
    `    <filter id="dfa-glow" x="-30%" y="-30%" width="160%" height="160%">`,
    `      <feGaussianBlur stdDeviation="4" result="blur" />`,
    `      <feComposite in="SourceGraphic" in2="blur" operator="over" />`,
    `    </filter>`,
    `    <marker id="dfa-arrow-solid" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">`,
    `      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#94a3b8" />`,
    `    </marker>`,
    `    <marker id="dfa-arrow-gold" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">`,
    `      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#fbbf24" />`,
    `    </marker>`,
    `    <marker id="dfa-arrow-start" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">`,
    `      <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#38bdf8" />`,
    `    </marker>`,
    `  </defs>`,
    `  <g class="dfa-edges">`,
  ];

  for (const ed of edgeRenders) {
    const stroke = ed.isHighlightedEdge ? '#fbbf24' : '#94a3b8';
    const strokeW = ed.isHighlightedEdge ? '2.6' : '1.8';
    const marker = ed.isHighlightedEdge ? 'dfa-arrow-gold' : 'dfa-arrow-solid';
    const lblW = Math.max(18, ed.label.length * 7.2 + 8);
    const lblTextColor = ed.isHighlightedEdge ? '#fef08a' : '#38bdf8';

    svgParts.push(
      `    <path d="${ed.pathD}" fill="none" stroke="${stroke}" stroke-width="${strokeW}" marker-end="url(#${marker})" />`,
      `    <rect x="${(ed.lblX - lblW / 2).toFixed(1)}" y="${(ed.lblY - 8).toFixed(1)}" width="${lblW.toFixed(1)}" height="15" rx="3" fill="#090d16" fill-opacity="0.9" />`,
      `    <text x="${ed.lblX.toFixed(1)}" y="${(ed.lblY + 3.5).toFixed(1)}" text-anchor="middle" fill="${lblTextColor}" font-size="11" font-weight="600" font-family="'JetBrains Mono', monospace">${escapeXml(ed.label)}</text>`
    );
  }

  const startPos = nodePos.get(startId)!;
  svgParts.push(
    `    <line x1="${(startPos.x - NODE_RADIUS - 38).toFixed(1)}" y1="${startPos.y.toFixed(1)}" x2="${(startPos.x - NODE_RADIUS - 4).toFixed(1)}" y2="${startPos.y.toFixed(1)}" stroke="#38bdf8" stroke-width="2.0" marker-end="url(#dfa-arrow-start)" />`,
    `    <text x="${(startPos.x - NODE_RADIUS - 44).toFixed(1)}" y="${(startPos.y + 4).toFixed(1)}" text-anchor="end" fill="#38bdf8" font-size="10.5" font-weight="700" font-family="'JetBrains Mono', monospace">START</text>`
  );

  for (const [sid, pos] of nodePos.entries()) {
    const st = dfa.states.get(sid)!;
    const isActive = activeSet.has(sid);

    let fillColor = '#1e293b';
    let borderColor = '#475569';
    let textColor = '#f8fafc';
    let strokeW = 1.6;
    let filterAttr = '';

    if (isActive) {
      fillColor = '#78350f';
      borderColor = '#fbbf24';
      textColor = '#fef08a';
      strokeW = 2.6;
      filterAttr = ' filter="url(#dfa-glow)"';
    } else if (st.isAccept) {
      fillColor = '#064e3b';
      borderColor = '#22c55e';
      textColor = '#86efac';
      strokeW = 2.0;
    } else if (st.isStart) {
      fillColor = '#1e3a8a';
      borderColor = '#38bdf8';
      textColor = '#ffffff';
      strokeW = 2.0;
    }

    const subsetText =
      dfa.kind === 'MINIMAL'
        ? `{${st.powersetStateIds.map((d) => 'D' + d).join(',')}}`
        : `{${st.nfaStateIds.map((q) => 'q' + q).join(',')}}`;
    const shortSubset = subsetText.length > 14 ? subsetText.slice(0, 13) + '…}' : subsetText;

    svgParts.push(
      `    <g class="dfa-node-group cursor-pointer" data-dfa-id="${sid}" data-dfa-kind="${dfa.kind}">`,
      `      <circle cx="${pos.x.toFixed(1)}" cy="${pos.y.toFixed(1)}" r="${NODE_RADIUS}" fill="${fillColor}" stroke="${borderColor}" stroke-width="${strokeW}"${filterAttr}>`,
      `        <title>${st.name}: NFA Subset {${st.nfaStateIds.map((q) => 'q' + q).join(', ')}} | Powerset {${st.powersetStateIds.map((d) => 'D' + d).join(', ')}}</title>`,
      `      </circle>`
    );
    if (st.isAccept) {
      svgParts.push(
        `      <circle cx="${pos.x.toFixed(1)}" cy="${pos.y.toFixed(1)}" r="${NODE_RADIUS - 4}" fill="none" stroke="${isActive ? '#fbbf24' : '#22c55e'}" stroke-width="1.4" />`
      );
    }
    svgParts.push(
      `      <text x="${pos.x.toFixed(1)}" y="${(pos.y + 4.5).toFixed(1)}" text-anchor="middle" fill="${textColor}" font-size="12.5" font-weight="600" font-family="'JetBrains Mono', monospace">${st.name}</text>`
    );

    if (showSubsets) {
      svgParts.push(
        `      <text x="${pos.x.toFixed(1)}" y="${(pos.y + NODE_RADIUS + 13).toFixed(1)}" text-anchor="middle" fill="#94a3b8" font-size="9.5" font-family="'JetBrains Mono', monospace">${escapeXml(shortSubset)}</text>`
      );
    }

    if (st.matchedRules && st.matchedRules.length > 0) {
      svgParts.push(
        `      <text x="${pos.x.toFixed(1)}" y="${(pos.y - NODE_RADIUS - 7).toFixed(1)}" text-anchor="middle" fill="#f43f5e" font-size="9.5" font-weight="700" font-family="'JetBrains Mono', monospace">[${escapeXml(st.matchedRules.join(','))}]</text>`
      );
    }

    svgParts.push(`    </g>`);
  }

  svgParts.push(`  </g>`);
  svgParts.push(`</svg>`);
  return svgParts.join('\n');
}

// ============================================================================
// 4. Academic & Engineering Exporters (Graphviz DOT, LaTeX TikZ, ASCII Tables)
// ============================================================================

export function exportGraphvizDot(
  nfa: CompiledNFA,
  dfa: CompiledDFA,
  mode: 'NFA' | 'DFA' = 'DFA',
  title = 'FINIX_Automaton'
): string {
  if (mode === 'NFA') {
    const lines = [
      `digraph NFA {`,
      `    rankdir=LR;`,
      `    label="${title} (Thompson ε-NFA)";`,
      `    labelloc="t";`,
      `    node [shape = circle, fontname="JetBrains Mono", style=filled, fillcolor="#1e293b", fontcolor="#f8fafc", color="#38bdf8"];`,
      `    edge [fontname="JetBrains Mono", color="#94a3b8", fontcolor="#38bdf8"];`,
      `    __start__ [shape=point, style=invis];`,
      `    __start__ -> q${nfa.startStateId};`,
    ];
    for (const st of nfa.states.values()) {
      if (st.isAccept) {
        lines.push(`    q${st.id} [shape = doublecircle, fillcolor="#064e3b", color="#22c55e"];`);
      }
    }
    for (const st of nfa.states.values()) {
      for (const tr of st.transitions) {
        const style = tr.symbolKind === 'EPSILON' ? ' [color="#c084fc", fontcolor="#c084fc", style=dashed]' : '';
        lines.push(`    q${st.id} -> q${tr.targetId} [label="${tr.display}"]${style};`);
      }
    }
    lines.push(`}`);
    return lines.join('\n');
  }

  const lines = [
    `digraph DFA {`,
    `    rankdir=LR;`,
    `    label="${title} (${dfa.kind} DFA)";`,
    `    labelloc="t";`,
    `    node [shape = circle, fontname="JetBrains Mono", style=filled, fillcolor="#1e293b", fontcolor="#f8fafc", color="#38bdf8"];`,
    `    edge [fontname="JetBrains Mono", color="#94a3b8", fontcolor="#38bdf8"];`,
    `    __start__ [shape=point, style=invis];`,
    `    __start__ -> ${dfa.states.get(dfa.startStateId)?.name ?? 'M0'};`,
  ];
  for (const st of dfa.states.values()) {
    if (st.isAccept) {
      lines.push(`    ${st.name} [shape = doublecircle, fillcolor="#064e3b", color="#22c55e"];`);
    }
  }
  for (const st of dfa.states.values()) {
    for (const [sym, tgt] of st.transitions.entries()) {
      const tgtName = dfa.states.get(tgt)?.name ?? `M${tgt}`;
      lines.push(`    ${st.name} -> ${tgtName} [label="${sym}"];`);
    }
  }
  lines.push(`}`);
  return lines.join('\n');
}

export function exportLatexTikz(dfa: CompiledDFA, regex: string): string {
  const lines = [
    `% LaTeX TikZ Automaton Diagram generated by FINIX Ω`,
    `% Pattern: ${regex}`,
    `\\documentclass[tikz,border=10pt]{standalone}`,
    `\\usetikzlibrary{automata, positioning, arrows.meta}`,
    `\\begin{document}`,
    `\\begin{tikzpicture}[->, >=Stealth, shorten >=1pt, auto, node distance=2.6cm, semithick]`,
    `  \\tikzstyle{every state}=[fill=slate!10, draw=black, text=black, font=\\ttfamily]`,
  ];

  const sids = Array.from(dfa.states.keys()).sort((a, b) => a - b);
  sids.forEach((sid, idx) => {
    const st = dfa.states.get(sid)!;
    const flags = [st.isStart ? 'initial' : '', st.isAccept ? 'accepting' : '']
      .filter(Boolean)
      .join(', ');
    const pos = idx === 0 ? '' : `[right of=${dfa.states.get(sids[idx - 1])!.name}]`;
    lines.push(`  \\node[state${flags ? ', ' + flags : ''}] (${st.name}) ${pos} {$${st.name}$};`);
  });

  lines.push(``);
  lines.push(`  \\path`);
  const edgeLines: string[] = [];
  for (const sid of sids) {
    const st = dfa.states.get(sid)!;
    for (const [sym, tgt] of st.transitions.entries()) {
      const tgtName = dfa.states.get(tgt)!.name;
      const loopOpt = sid === tgt ? '[loop above]' : sid > tgt ? '[bend left=25]' : '';
      edgeLines.push(`    (${st.name}) edge ${loopOpt} node {\\ttfamily ${sym}} (${tgtName})`);
    }
  }
  lines.push(edgeLines.join('\n') + ';');
  lines.push(`\\end{tikzpicture}`);
  lines.push(`\\end{document}`);
  return lines.join('\n');
}

export function generateAsciiTransitionTable(nfa: CompiledNFA, dfa: CompiledDFA): string {
  const cols = dfa.alphabetLabels;
  const colW = 14;
  const header =
    `${'State'.padEnd(10)} | ${'NFA Subset'.padEnd(20)} | ` +
    cols.map((c) => c.padStart(Math.floor((colW + c.length) / 2)).padEnd(colW)).join(' | ');
  const sep = '-'.repeat(header.length);
  const rows = [
    `=== FORMAL TRANSITION TABLE (${dfa.kind} DFA: |Q|=${dfa.states.size}, |Σ/~|=${cols.length}) ===`,
    header,
    sep,
  ];

  for (const st of dfa.states.values()) {
    const prefix =
      st.isStart && st.isAccept ? '->* ' : st.isStart ? '->  ' : st.isAccept ? ' *  ' : '    ';
    const subsetStr = `{${st.nfaStateIds.map((q) => 'q' + q).join(',')}}`;
    const cells = cols.map((sym) => {
      const tgt = st.transitions.get(sym);
      const cell = tgt !== undefined ? dfa.states.get(tgt)!.name : '∅';
      return cell.padStart(Math.floor((colW + cell.length) / 2)).padEnd(colW);
    });
    rows.push(
      `${(prefix + st.name).padEnd(10)} | ${subsetStr.slice(0, 20).padEnd(20)} | ${cells.join(' | ')}`
    );
  }
  return rows.join('\n');
}

export function generateAsciiSimulationTrace(sim: DualSimulationResult): string {
  const lines = [
    `Initial ε-NFA Closure : {${sim.nfaInitialStates.map((q) => 'q' + q).join(', ')}}`,
    `Initial Minimal DFA   : M${sim.minimalInitialState}`,
    ``,
  ];
  const header = `${'Step'.padEnd(5)} | ${'Char'.padEnd(6)} | ${'NFA Active (Before)'.padEnd(22)} | ${'Direct MOVE'.padEnd(16)} | ${'ε-Additions'.padEnd(16)} | ${'NFA (After ε)'.padEnd(22)} | ${'Min DFA'.padEnd(10)}`;
  const sep = '-'.repeat(header.length);
  lines.push(header, sep);

  for (const st of sim.steps) {
    const bStr = `{${st.nfaBefore.map((q) => 'q' + q).join(',')}}`;
    const dStr = st.nfaDirectMove.length ? `{${st.nfaDirectMove.map((q) => 'q' + q).join(',')}}` : '∅';
    const eStr = st.nfaEpsilonAdditions.length
      ? `{${st.nfaEpsilonAdditions.map((q) => 'q' + q).join(',')}}`
      : '∅';
    const aStr = st.nfaAfter.length ? `{${st.nfaAfter.map((q) => 'q' + q).join(',')}}` : '∅ (Dead)';
    const mStr =
      st.minimalBefore !== null
        ? `M${st.minimalBefore}->${st.minimalAfter !== null ? 'M' + st.minimalAfter : '∅'}`
        : '∅';
    lines.push(
      `${String(st.stepIndex).padEnd(5)} | ${("'" + st.char + "'").padEnd(6)} | ${bStr.slice(0, 22).padEnd(22)} | ${dStr.slice(0, 16).padEnd(16)} | ${eStr.slice(0, 16).padEnd(16)} | ${aStr.slice(0, 22).padEnd(22)} | ${mStr.padEnd(10)}`
    );
  }

  lines.push(sep);
  lines.push(
    `Verdict: ${sim.isAccepted ? '✓ ACCEPTED' : '✗ REJECTED'} (${sim.elapsedMs.toFixed(3)} ms)`
  );
  return lines.join('\n');
}
