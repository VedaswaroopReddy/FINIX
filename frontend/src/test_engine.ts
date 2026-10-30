/**
 * test_engine.ts: End-to-end verification of all TypeScript automata and SIEM engines.
 */
import {
  compileRegexPipeline,
  simulateDualExecution,
  proveRegexEquivalence
} from './engine/automataEngine';
import {
  DEFAULT_SIEM_SIGNATURES,
  compileMasterSIEMAutomaton,
  scanLogLineSinglePass
} from './engine/siemEngine';
import {
  generateNfaSvg,
  generateDfaSvg,
  exportGraphvizDot,
  exportLatexTikz
} from './engine/svgVisualizer';

console.log("=== FINIX TypeScript Engine Verification ===");

// 1. Full Pipeline Compilation
console.log("\n[1] Testing compileRegexPipeline('(a|b)*abb')...");
const comp = compileRegexPipeline('(a|b)*abb');
console.log(`  - AST Root: ${comp.ast.kind} (${comp.ast.label})`);
console.log(`  - NFA States: ${comp.nfa.states.size}`);
console.log(`  - Powerset DFA States: ${comp.powersetDfa.states.size}`);
console.log(`  - Hopcroft Min-DFA States: ${comp.minimalDfa.states.size}`);
console.log(`  - Compilation Time: ${comp.compileTimeMs.toFixed(3)} ms`);
if (comp.minimalDfa.states.size !== 4) {
  throw new Error(`Expected 4 minimal DFA states, got ${comp.minimalDfa.states.size}`);
}
console.log("  [PASS] Pipeline compilation verified.");

// 2. Dual-Automata Step Simulator
console.log("\n[2] Testing simulateDualExecution with 'ababb'...");
const sim = simulateDualExecution(comp, 'ababb');
console.log(`  - Is Accepted: ${sim.isAccepted}`);
console.log(`  - Step Count: ${sim.steps.length}`);
console.log(`  - Minimal Final State: M${sim.minimalFinalState}`);
if (!sim.isAccepted) {
  throw new Error("Simulation failed to accept 'ababb'!");
}
console.log("  [PASS] Dual-automata lockstep simulation verified.");

// 3. Automated Theorem Prover & Counterexample Synthesis
console.log("\n[3] Testing proveRegexEquivalence('a+', 'a*')...");
const proof = proveRegexEquivalence('a+', 'a*');
console.log(`  - Equivalent: ${proof.isEquivalent}`);
console.log(`  - Relation: ${proof.relationSummary}`);
console.log(`  - Witness L2 \\ L1: ${JSON.stringify(proof.witness2Minus1)}`);
if (proof.isEquivalent !== false || proof.witness2Minus1 !== "") {
  throw new Error("Theorem prover failed to synthesize epsilon witness!");
}
console.log("  [PASS] Equivalence prover and shortest counterexample witness verified.");

// 4. Multi-Pattern SIEM Engine
console.log("\n[4] Testing compileMasterSIEMAutomaton & scanLogLineSinglePass...");
const master = compileMasterSIEMAutomaton(DEFAULT_SIEM_SIGNATURES);
console.log(`  - Master DFA Signatures Compiled: ${master.rules.length}`);
console.log(`  - Master DFA State Count: ${master.minimizedMasterDfa.states.size}`);

const traversalLog = `45.155.205.233 - - [28/Oct/2026:10:14:09 +0000] "GET /cgi-bin/../../etc/passwd HTTP/1.1" 403 284`;
const inc = scanLogLineSinglePass(master, traversalLog, 1);
console.log(`  - Incident Flagged: ${inc.matchedRules.length > 0}`);
console.log(`  - Incident Threat: ${inc.highestThreat}`);
console.log(`  - Matched Rules: ${inc.matchedRules.map(r => r.id).join(', ')}`);
if (inc.highestThreat !== 'CRITICAL' || !inc.matchedRules.some(r => r.id === 'SEC-02')) {
  throw new Error("SIEM scanner failed to flag directory traversal log line!");
}
console.log("  [PASS] Single-pass SIEM log scanner verified.");

// 5. SVG Visualizer & Exporters
console.log("\n[5] Testing SVG visualizers & Graphviz/LaTeX exporters...");
const nfaSvg = generateNfaSvg(comp.nfa);
const dfaSvg = generateDfaSvg(comp.minimalDfa);
const dot = exportGraphvizDot(comp.nfa, comp.minimalDfa, 'DFA');
const tikz = exportLatexTikz(comp.minimalDfa, '(a|b)*abb');
console.log(`  - NFA SVG Length: ${nfaSvg.length} chars`);
console.log(`  - DFA SVG Length: ${dfaSvg.length} chars`);
console.log(`  - Graphviz DOT Length: ${dot.length} chars`);
console.log(`  - LaTeX TikZ Length: ${tikz.length} chars`);
if (!nfaSvg.includes('<svg') || !dfaSvg.includes('<svg') || !dot.includes('digraph') || !tikz.includes('\\begin{tikzpicture}')) {
  throw new Error("Visualizer SVG/DOT/TikZ export failed!");
}
console.log("  [PASS] SVG rendering, Graphviz DOT, and LaTeX TikZ generation verified.");

console.log("\n>>> ALL 5 FRONTEND TYPESCRIPT MODULES VERIFIED & WORKING 100% <<<");
