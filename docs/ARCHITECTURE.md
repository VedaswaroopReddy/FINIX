# FINIX — System Architecture & Formal Engine Design

FINIX is a linear-time regular expression compiler, interactive automata visualizer, step debugger, and SIEM multi-pattern log scanner. It translates extended regular expressions through the formal automata hierarchy: Extended AST $\to$ Thompson $\varepsilon$-NFA $\to$ Rabin-Scott Powerset DFA $\to$ Hopcroft Minimal DFA.

---

## 1. Core Architectural Pipeline

```
┌────────────────────────────────────────────────────────────────────────┐
│                        FINIX SYSTEM ARCHITECTURE                       │
│       [Pipeline] · [Step Debugger] · [Minimization] · [SIEM Scanner]   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                       AUTOMATA COMPILER KERNEL                         │
│  ┌──────────────┐   ┌────────────────┐   ┌──────────────┐              │
│  │ Lexer +      │──▶│ Minterm        │──▶│ Thompson     │              │
│  │ Shunting-Yard│   │ Partitioner    │   │ ε-NFA        │              │
│  │ ({n,m}, &, ~)│   │ (Σ / ~ Classes)│   │ Linear |Q|   │              │
│  └──────────────┘   └────────────────┘   └──────┬───────┘              │
│                                                 │                      │
│  ┌──────────────────────────────────────────────▼───────────────────┐  │
│  │ Rabin-Scott Powerset DFA (Subset Construction over Minterms)     │  │
│  └──────────────────────────────────────────────┬───────────────────┘  │
│                                                 │                      │
│  ┌──────────────────────────────────────────────▼───────────────────┐  │
│  │ Hopcroft Partition Refinement (O(|Σ|·n log n) Canonical Min-DFA) │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
┌──────────────────┐    ┌──────────────────────┐    ┌──────────────────────┐
│ AUTOMATA PIPELINE│    │  STEP DEBUGGER &     │    │  SIEM MULTI-PATTERN  │
│ & EXPORTER       │    │  EQUIVALENCE PROVER  │    │  LOG SCANNER         │
│ • 4-Stage Grid   │    │ • Dual-Track Step    │    │ • Unified Moore DFA  │
│ • TikZ / DOT Exp │    │ • Counterexample BFS │    │ • Single-Pass Stream │
└──────────────────┘    └──────────────────────┘    └──────────────────────┘
```

---

## 2. Key Components

### 2.1 Lexical Analysis & Minterm Partitioning ($\Sigma / \sim$)
- Tokenizes extended POSIX patterns including concatenation, alternation (`|`), Kleene star (`*`), positive closure (`+`), option (`?`), and bounded quantifiers (`{n}`, `{n,}`, `{n,m}`).
- Computes disjoint alphabet minterm equivalence classes ($\Sigma / \sim$) across all literal and range characters, avoiding brute-force ASCII iteration.

### 2.2 Thompson $\varepsilon$-NFA Construction
- Builds inductive $\varepsilon$-NFA gadgets with linear state bounds $|Q| \le 2|r|$.
- Maintains strict start and accept state invariants for inductive composition.

### 2.3 Rabin-Scott Powerset Determinization
- Computes parallel $\varepsilon$-closures over minterm equivalence classes.
- Produces deterministic transition tables with exact subset mapping.

### 2.4 Hopcroft Minimization & Language Equivalence Prover
- Executes worklist partition refinement in $O(|\Sigma| \cdot n \log n)$ time.
- Records step-by-step split traces $(S, c)$ and inverse preimage sets.
- Synthesizes lexicographically shortest counterexample witness strings for non-equivalent regular expressions using product automaton BFS.

### 2.5 Unified Moore Master DFA for SIEM Log Scanning
- Compiles multiple security signatures into a single Moore DFA where each state stores the set of triggered rule IDs.
- Scans input streams in a single linear pass $O(|w|)$, eliminating redundant per-rule regex scans.

---

## 3. Web Dashboard

The web interface is organized into 4 workspaces:
1. **Pipeline**: Visualizes the 4 representation stages (AST, Thompson NFA, Powerset DFA, Minimal DFA) with cross-stage subset mapping and artifact export (LaTeX TikZ, Graphviz DOT, ASCII tables).
2. **Step Debugger**: Interactive step-by-step execution tracking NFA active sets alongside the DFA path.
3. **Minimization & Equivalence**: Hopcroft partition refinement trace and regex equivalence prover with shortest counterexample witness synthesis.
4. **SIEM Scanner**: Multi-pattern log stream inspection using the unified Moore Master DFA.
