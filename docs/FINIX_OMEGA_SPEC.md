# FINIX Ω — Formal Automata Compiler, Equivalence Prover & Single-Pass SIEM Workbench

FINIX Ω transforms the original regex-to-automata script set into a compiler engineering workbench and formal verification studio. It pairs a complete in-browser formal language compiler, interactive 4-stage automata visualizer, Hopcroft partition debugger, counterexample theorem prover, and true $O(|w|)$ multi-pattern SIEM scanner with a one-click export of the upgraded Python codebase.

## User Review & Critical Decisions

> [!IMPORTANT]
> All core architectural and design choices from Phase 1 have been locked into the specification below. Review the algorithmic upgrades and interactive workbench flows before execution begins.

- **Confirmed Decision 1 — Deliverable & Experience**: Full interactive Web Workbench paired with an upgraded, production-ready Python suite inspector and downloader (`parser.py`, `nfa.py`, `thompson.py`, `dfa.py`, `minimizer.py`, `simulator.py`, `visualizer.py`, `security.py`, `scanner.py`).
- **Confirmed Decision 2 — Algorithmic & Formal Theory Upgrades**:
  - Extended regular expression grammar supporting bounded quantifiers (`{n}`, `{n,}`, `{n,m}`), anchors (`^`, `$`), boolean set operations (`&` intersection, `~` complement), and **Alphabet Minterm / Equivalence Class Compression** ($\Sigma / \sim$) so powerset construction operates over disjoint character partitions rather than brute-forcing 128 ASCII chars.
  - **Symmetric Difference Witness Synthesizer** ($L(r_1) \oplus L(r_2)$) that computes the lexicographically shortest counterexample strings in $L(r_1) \setminus L(r_2)$ and $L(r_2) \setminus L(r_1)$ alongside inclusion ($L(r_1) \subseteq L(r_2)$) and intersection proofs.
  - **True Single-Pass $O(|w|)$ Multi-Rule Master DFA** using tag-set partitioned Moore-machine Hopcroft minimization—fixing the original `scanner.py` flaw where `scan_target()` fell back to an $O(K \cdot |w|)$ loop over individual rules.
- **Confirmed Decision 3 — Interactive Visualization & Debugging**:
  - Synchronized 4-Stage Pipeline View (`AST` $\to$ `Thompson ε-NFA` $\to$ `Rabin-Scott Powerset DFA` $\to$ `Hopcroft Minimal DFA`) with interactive pan/zoom, Sugiyama crossing-minimization layout, and cross-stage state highlighting.
  - Interactive Step-by-Step **Hopcroft Partition Refinement Visualizer** showing splitter pairs $(S, c)$, inverse preimages $\delta^{-1}(S, c)$, block splits $Y \to (Y \cap X, Y \setminus X)$, and the Myhill-Nerode distinguishability table with pairwise distinguishing suffixes.
  - **Live Dual-Trace Step Debugger** scrubbing character-by-character across any test string, simultaneously animating parallel $\varepsilon$-NFA state sets ($\text{MOVE}(S,c)$ + $\varepsilon\text{-closure}$) and deterministic DFA state transitions.
- **Confirmed Decision 4 — Visual Aesthetic Direction**: Dark high-contrast compiler engineering studio (`#090D16` obsidian canvas, `#111827` slate structural panels, crisp `1px` borders, `Bricolage Grotesque` + `Plus Jakarta Sans` + `JetBrains Mono` tabular typography).

---

## 1. Overview & Core Concept

- **What It Does**: Compiles extended regular expressions from first principles through lexical analysis, algebraic AST construction, minterm alphabet partitioning, Thompson $\varepsilon$-NFA synthesis, Rabin-Scott powerset determinization, and Hopcroft $O(|\Sigma| \cdot |Q| \log |Q|)$ partition refinement. It provides live interactive debugging, automated theorem proving with witness generation, single-pass SIEM log forensics, and full Python/LaTeX/DOT code export.
- **Target Audience / Persona**: Compiler engineers, formal verification researchers, computer science educators, and security engineers building zero-ReDoS deterministic packet and log inspection engines.
- **Key Value**: Eliminates the black-box gap between theoretical automata textbooks and high-throughput production regex engines (like RE2 and Hyperscan) by making every intermediate data structure, equivalence class, partition split, and multi-rule DFA transition inspectable in real time.

---

## 2. User Experience & Visual Design

### Key User Flows

1. **Compiler & 4-Stage Synchronized Graph Studio**:
   - The user enters or selects a preset regular expression (e.g., `^(https?)://[a-z0-9.-]+\.(exe|sh|bat)$`, `(a|b)*abb`, or `a{2,4}b+`) in the top compiler bar.
   - The compiler immediately parses tokens, computes disjoint alphabet minterms ($\Sigma / \sim$), builds the AST, synthesizes the $\varepsilon$-NFA, determinizes to a Powerset DFA, and minimizes to a canonical Quotient DFA.
   - Users can view any stage full-screen or switch to the **Synchronized 4-Stage Split View**. Hovering over a Minimal DFA macro-state $M_k$ highlights the merged Powerset states $\{D_i\}$ and the underlying $\varepsilon$-NFA state subset $\{q_j\}$ simultaneously.
   - An Export Drawer provides instant copy/download of **LaTeX TikZ**, **Graphviz DOT**, **Formal ASCII Transition Tables**, and **SVG**.
2. **Live Dual-Trace Execution Debugger**:
   - Users type a test payload and scrub through execution step-by-step (`Step 0: Initial ε-Closure` $\to$ `Step k: Char c`) or use auto-play with adjustable speed.
   - The top track highlights the active $\varepsilon$-NFA state set (distinguishing direct `MOVE(S, c)` targets in cyan from $\varepsilon$-closure additions in violet), while the bottom track highlights the active Minimal DFA state and transition edge in gold.
3. **Hopcroft Minimization & Equivalence Theorem Prover**:
   - **Hopcroft Refiner Mode**: Walks through each iteration of Hopcroft's worklist algorithm. Selecting step $t$ shows the active splitter $(S, c)$, the preimage set $X = \delta^{-1}(S, c)$, which partition block $P_i$ fractured into $P_{i,1}$ and $P_{i,2}$, and the complete **Myhill-Nerode Distinguishability Matrix** showing the exact shortest suffix $w$ that distinguishes any two states $p \not\equiv q$.
   - **Equivalence & Witness Prover Mode**: Users enter two regular expressions $r_1$ and $r_2$. The prover builds the canonical Minimal DFAs and the product automata for $L(r_1) \setminus L(r_2)$, $L(r_2) \setminus L(r_1)$, and $L(r_1) \cap L(r_2)$. If $L(r_1) \not\equiv L(r_2)$, it outputs the **shortest counterexample witness strings** and demonstrates them on both automata.
4. **Single-Pass $O(|w|)$ Master DFA SIEM Log Forensics**:
   - Compiles all $K$ security signatures (plus user-defined custom rules) into a **Unified Multi-Output Master DFA** where every state stores a bitmask/set of triggered `SIEMRule` IDs.
   - Users scan realistic Apache/Nginx access log streams or custom HTTP payloads in a single deterministic pass per line, inspecting the exact Master DFA state trajectory, rule hit heatmaps, and ReDoS immunity benchmarks ($O(|w|)$ deterministic vs. exponential backtracking).
5. **Upgraded Python 3.12+ Architecture Suite & Exporter**:
   - Interactive code browser and downloader containing the complete, upgraded 9-module Python package (`nfa.py`, `parser.py`, `thompson.py`, `dfa.py`, `minimizer.py`, `simulator.py`, `visualizer.py`, `security.py`, `scanner.py`) with all algorithmic fixes, type annotations, and docstrings ready to run locally.

### Visual Identity & Theme

- **Aesthetic Direction**: Dark high-contrast compiler engineering studio inspired by precision logic analyzers and formal verification IDEs.
- **Color Palette & Mood (60-30-10 Allocation)**:
  - **60% Dominant Canvas**: Deep Obsidian Slate (`#090D16`) background with subtle coordinate grid canvas (`#0F172A`) for graph viewports.
  - **30% Structural Surfaces**: Slate Studio Panels (`#111827`) with crisp `1px solid #1E293B` hairline dividers and `#F8FAFC` primary / `#94A3B8` secondary typography.
  - **10% Semantic Focal Accents** (always paired with explicit text labels/glyphs):
    - Start State / Direct Move: Cerulean Cyan (`#38BDF8`)
    - $\varepsilon$-Transition / Closure Addition: Electric Violet (`#C084FC`)
    - Active Trace / Splitter Focus: Precision Amber (`#FBBF24`)
    - Accepting State / Verified Equivalent: Emerald Mint (`#22C55E`)
    - Counterexample / Critical SIEM Threat: Coral Crimson (`#F43F5E`)
- **Typography & Hierarchy (2+1 Font Rule)**:
  - *Display & Navigation*: `Bricolage Grotesque` (600/700, tight tracking)
  - *UI Body & Analytical Explanations*: `Plus Jakarta Sans` (400/500/600)
  - *Automata States, Formal Tuples, Regex Input & Tabular Metrics*: `JetBrains Mono` with `font-variant-numeric: tabular-nums`
- **Component Styling & Layout**:
  - Full-viewport `1440px+` studio layout adhering to the strict **Top Bar Contract** (Zone 1: `FINIX Ω` wordmark; Zone 2: 5 single-line workspace links `Pipeline Studio`, `Dual Debugger`, `Hopcroft & Prover`, `SIEM Master DFA`, `Python Suite`; Zone 3: `Export Artifacts` primary button).
  - Single-elevation surfaces (`border border-slate-800 bg-slate-900/90`) with zero nested card-in-card clutter and unboxed metadata separated by `·`.

---

## 3. Key Product Decisions & Trade-Offs

- **Decision 1: Alphabet Minterm Partitioning ($\Sigma / \sim$) over Brute-Force ASCII Iteration**
  - *Chosen Approach*: Extract all character intervals and literals during lexical analysis and compute their minimal disjoint boolean intersections (minterms) before powerset construction.
  - *Why*: The original code iterated over all 128 ASCII characters for every DFA state, creating hundreds of redundant edges and slowing browser/Python compilation. Minterm compression groups equivalent characters (e.g., `[a-z]`, `[0-9]`, `Σ \ {a..z}`) into compact equivalence classes, speeding up DFA construction by 15–40x and producing clean, readable transition tables.
- **Decision 2: Tag-Preserving Moore Machine Minimization for the SIEM Master DFA**
  - *Chosen Approach*: Initialize Hopcroft's initial partition $P_0$ by grouping DFA states according to their exact tuple of matched `SIEMRule` IDs rather than a binary `{Accept, Non-Accept}` split, and execute `scan_target()` directly on the Master DFA jump table.
  - *Why*: Fixes the critical flaw in the original `scanner.py` where `MasterSecurityDFA` was constructed unused and `scan_target()` fell back to testing each rule's DFA sequentially in $O(K \cdot |w|)$.
- **Decision 3: Product Automaton BFS for Shortest Counterexample Synthesis**
  - *Chosen Approach*: Construct the product DFA $M_1 \times M_2$ over the unified minterm alphabet and run breadth-first search to find the shortest paths to states in $(F_1 \times \overline{F_2})$ and $(\overline{F_1} \times F_2)$.
  - *Why*: BFS over a deterministic graph with sorted minterm representatives guarantees finding the lexicographically shortest witness string in $O(|Q_1| \cdot |Q_2| \cdot |\Sigma/\sim|)$ time.

---

## 4. Technical Architecture & Data Strategy

### Architecture & Component Diagram

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                         TOP BAR (3-Zone Strict Contract)                          │
│  [FINIX Ω]     [Pipeline · Debugger · Hopcroft & Prover · SIEM · Python Suite]    │
└─────────────────────────────────────────┬─────────────────────────────────────────┘
                                          │
┌─────────────────────────────────────────▼─────────────────────────────────────────┐
│                    GLOBAL REGEX & FORMAL COMPILER KERNEL (TS)                     │
│  ┌──────────────┐   ┌────────────────┐   ┌──────────────┐   ┌──────────────────┐  │
│  │ Lexer +      │──▶│ Minterm        │──▶│ Thompson     │──▶│ Rabin-Scott      │  │
│  │ Shunting-Yard│   │ Partitioner    │   │ ε-NFA Builder│   │ Powerset DFA     │  │
│  │ ({n,m}, &, ~)│   │ (Σ / ~ Classes)│   │ (Linear |Q|) │   │ (Subset Mapping) │  │
│  └──────────────┘   └────────────────┘   └──────────────┘   └────────┬─────────┘  │
│                                                                      │            │
│  ┌───────────────────────────────────────────────────────────────────▼─────────┐  │
│  │ Hopcroft Partition Refiner (Step Trace + Myhill-Nerode Matrix + Minimal DFA)│  │
│  └──────────────┬───────────────────────┬──────────────────────────┬───────────┘  │
└─────────────────┼───────────────────────┼──────────────────────────┼──────────────┘
                  │                       │                          │
      ┌───────────▼──────────┐ ┌──────────▼───────────┐ ┌────────────▼───────────┐
      │  4-STAGE PIPELINE &  │ │ HOPCROFT ANIMATOR &  │ │  TRUE O(|w|) MASTER    │
      │  DUAL-TRACE DEBUGGER │ │ WITNESS PROVER (⊕)   │ │  DFA SIEM & PYTHON IDE │
      │ • Synced AST/NFA/DFA │ │ • Worklist Stepper   │ │ • Multi-Tag Moore DFA  │
      │ • Sugiyama SVG Pan   │ │ • Distinguishability │ │ • Live Log Streamer    │
      │ • NFA vs DFA Scrubber│ │ • Counterexample BFS │ │ • 9-File Python Export │
      └──────────────────────┘ └──────────────────────┘ └────────────────────────┘
```

### Data Model & State

- **`RegexCompilerOutput`**: Holds raw tokens, explicit-concat tokens, postfix RPN, `ASTNode` hierarchy, disjoint `MintermClass[]`, compiled `NFA`, `PowersetDFA`, `MinimalDFA`, `HopcroftRefinementTrace` (list of partition states, splitters, preimages), and `MyhillNerodeTable` (pairwise distinguishing strings).
- **`DualSimulationTrace`**: Synchronized array of character steps containing `nfaBefore`, `nfaDirectMove`, `nfaEpsilonAdditions`, `nfaAfter`, `powersetStateId`, `minimalStateId`, and acceptance flags.
- **`EquivalenceProofResult`**: Contains `isEquivalent`, `isSubsetL1OfL2`, `isSubsetL2OfL1`, `isDisjoint`, `witnessL1MinusL2` (shortest string in $L(r_1) \setminus L(r_2)$), `witnessL2MinusL1` (shortest string in $L(r_2) \setminus L(r_1)$), `intersectionWitness`, and both compiled minimal automata.
- **`MasterSIEMEngine`**: Holds the rule catalog (`SIEMRule[]`), the compiled single-pass `MasterDFA` where each state maps to `matchedRuleIds: string[]`, and batch log analysis forensics (`LogIncident[]`, per-character state trajectory, throughput telemetry).

### Interactive Component & State Mapping

- **Compiler Input & Preset Bar**: Live validation with exact character-index syntax pinpointing; instant recompilation across all views; preset selector covering textbook automata, pathological ReDoS patterns (`(a+)+b`), and network security signatures.
- **Interactive SVG Graph Viewport**: Supports mouse wheel zoom, drag pan, fit-to-screen, cross-stage state hover highlighting (hovering `M1` highlights its constituent `D` and `q` states), and export modal (`Graphviz DOT`, `LaTeX TikZ`, `ASCII Transition Table`, `Standalone SVG`).
- **Dual-Trace Step Controller**: Play/Pause, Step Forward/Back, Reset, speed selector, and interactive character ribbon click-to-jump.
- **Hopcroft & Equivalence Studio**: Step slider for Hopcroft partition splits; interactive Myhill-Nerode cell inspection (clicking cell $(D_i, D_j)$ loads their distinguishing suffix into the debugger); dual regex inputs with one-click counterexample simulation.
- **SIEM Master DFA Console**: Custom rule creator, multi-rule Master DFA graph & state-to-rule tag table, live Apache/Nginx log batch scanner, and interactive single-line packet trace inspector.
- **Upgraded Python Codebase Explorer**: Module switcher across all 9 upgraded Python files with architectural diff highlights ("Original vs. FINIX Ω Upgrade"), copy-to-clipboard, and bundled `.py` / archive download.
