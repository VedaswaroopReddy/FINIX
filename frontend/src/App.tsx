/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo, useEffect } from 'react';
import {
  Play,
  Pause,
  SkipBack,
  SkipForward,
  RotateCcw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Copy,
  Check,
  Download,
  Plus,
  Trash2,
  ArrowRight,
  Code2,
  ShieldAlert,
  GitCompare,
  Layers,
  Activity,
  X,
} from 'lucide-react';
import {
  COMPILER_PRESETS,
  compileRegexPipeline,
  proveRegexEquivalence,
  simulateDualExecution,
} from './engine/automataEngine';
import {
  exportGraphvizDot,
  exportLatexTikz,
  generateAsciiSimulationTrace,
  generateAsciiTransitionTable,
  generateAstSvg,
  generateDfaSvg,
  generateNfaSvg,
} from './engine/svgVisualizer';
import {
  DEFAULT_SIEM_SIGNATURES,
  SAMPLE_ACCESS_LOGS,
  SIEMRule,
  compileMasterSIEMAutomaton,
  scanLogLineSinglePass,
} from './engine/siemEngine';
import { UPGRADED_PYTHON_MODULES } from './engine/pythonSuiteContent';
import { InteractiveSvgCanvas } from './components/InteractiveSvgCanvas';

type WorkspaceTab = 'pipeline' | 'debugger' | 'prover' | 'siem' | 'python';
type PipelineStageMode = 'all4' | 'ast' | 'nfa' | 'powerset' | 'minimal';
type ExportFormat = 'tikz' | 'dot_dfa' | 'dot_nfa' | 'ascii_table' | 'ascii_trace';

const EQUIVALENCE_PRESETS = [
  {
    name: 'Kleene Denesting Identity',
    r1: '(a|b)*',
    r2: '(a*b*)*',
    note: 'Classic algebraic identity: both reduce to the 1-state universal DFA over {a,b}.',
  },
  {
    name: 'Shift-Slide Concatenation Identity',
    r1: 'a(ba)*',
    r2: '(ab)*a',
    note: 'Alternating string identity: both reduce to an identical 2-state Minimal DFA.',
  },
  {
    name: 'Subtle Suffix Difference (Non-Equivalent)',
    r1: '(a|b)*abb',
    r2: 'a*b*abb',
    note: 'Non-equivalent: r1 allows b before a in the prefix (shortest witness: "baabb").',
  },
  {
    name: 'Bounded Quantifier Unrolling Identity',
    r1: 'a{2,3}b+',
    r2: 'aabb*|aaabb*',
    note: 'Proves bounded quantifier {2,3} and positive closure + equal explicit unrolling.',
  },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<WorkspaceTab>('pipeline');

  // Global Regex & Test Input State
  const [regexInput, setRegexInput] = useState<string>('(a|b)*abb');
  const [testInput, setTestInput] = useState<string>('ababb');
  const [pipelineStageMode, setPipelineStageMode] = useState<PipelineStageMode>('all4');

  // Cross-Stage Hover State for Synchronized 4-Stage Pipeline View
  const [hoveredState, setHoveredState] = useState<{
    kind: 'NFA' | 'POW' | 'MIN';
    id: number;
  } | null>(null);

  // Dual Debugger Playback State
  const [debugStepIdx, setDebugStepIdx] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);

  // Hopcroft & Equivalence Prover State
  const [proverSubMode, setProverSubMode] = useState<'hopcroft' | 'equivalence'>('hopcroft');
  const [hopcroftStepCursor, setHopcroftStepCursor] = useState<number>(0);
  const [equivRegex1, setEquivRegex1] = useState<string>('(a|b)*abb');
  const [equivRegex2, setEquivRegex2] = useState<string>('a*b*abb');

  // SIEM Master DFA State
  const [siemRules, setSiemRules] = useState<SIEMRule[]>(DEFAULT_SIEM_SIGNATURES);
  const [logBatchText, setLogBatchText] = useState<string>(SAMPLE_ACCESS_LOGS.join('\n'));
  const [selectedIncidentLine, setSelectedIncidentLine] = useState<number>(3);
  const [newRuleName, setNewRuleName] = useState<string>('');
  const [newRulePattern, setNewRulePattern] = useState<string>('');
  const [newRuleThreat, setNewRuleThreat] = useState<SIEMRule['threatLevel']>('HIGH');
  const [newRuleCategory, setNewRuleCategory] = useState<string>('Custom Signature');
  const [siemRuleError, setSiemRuleError] = useState<string | null>(null);

  // Python Suite State
  const [selectedPythonFile, setSelectedPythonFile] = useState<string>('scanner.py');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Export Modal State
  const [isExportModalOpen, setIsExportModalOpen] = useState<boolean>(false);
  const [exportFormat, setExportFormat] = useState<ExportFormat>('tikz');

  // Compile main regex safely
  const compilationState = useMemo(() => {
    try {
      const result = compileRegexPipeline(regexInput);
      return { result, error: null };
    } catch (err: any) {
      return { result: null, error: err?.message || 'Invalid regular expression' };
    }
  }, [regexInput]);

  const compiled = compilationState.result;

  // Dual Simulation
  const simulation = useMemo(() => {
    if (!compiled) return null;
    return simulateDualExecution(compiled, testInput);
  }, [compiled, testInput]);

  // Clamp debugStepIdx when testInput changes
  useEffect(() => {
    setDebugStepIdx((prev) => Math.min(prev, testInput.length));
    setIsPlaying(false);
  }, [testInput, regexInput]);

  // Clamp hopcroftStepCursor when regex changes
  useEffect(() => {
    if (compiled) {
      setHopcroftStepCursor(compiled.hopcroftSteps.length - 1);
    }
  }, [compiled]);

  // Playback timer for Dual Debugger
  useEffect(() => {
    if (!isPlaying) return;
    const timer = window.setInterval(() => {
      setDebugStepIdx((prev) => {
        if (prev >= testInput.length) {
          setIsPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, 650);
    return () => window.clearInterval(timer);
  }, [isPlaying, testInput.length]);

  // Compute cross-stage synchronized highlight sets
  const crossStageHighlights = useMemo(() => {
    if (!compiled || !hoveredState) {
      return {
        nfaIds: new Set<number>(),
        powIds: new Set<number>(),
        minIds: new Set<number>(),
        summary: null,
      };
    }

    const nfaIds = new Set<number>();
    const powIds = new Set<number>();
    const minIds = new Set<number>();

    if (hoveredState.kind === 'MIN') {
      const mState = compiled.minimalDfa.states.get(hoveredState.id);
      if (mState) {
        minIds.add(mState.id);
        mState.powersetStateIds.forEach((d) => powIds.add(d));
        mState.nfaStateIds.forEach((q) => nfaIds.add(q));
      }
    } else if (hoveredState.kind === 'POW') {
      const dState = compiled.powersetDfa.states.get(hoveredState.id);
      if (dState) {
        powIds.add(dState.id);
        dState.nfaStateIds.forEach((q) => nfaIds.add(q));
        for (const mSt of compiled.minimalDfa.states.values()) {
          if (mSt.powersetStateIds.includes(dState.id)) {
            minIds.add(mSt.id);
          }
        }
      }
    } else if (hoveredState.kind === 'NFA') {
      nfaIds.add(hoveredState.id);
      for (const dSt of compiled.powersetDfa.states.values()) {
        if (dSt.nfaStateIds.includes(hoveredState.id)) {
          powIds.add(dSt.id);
        }
      }
      for (const mSt of compiled.minimalDfa.states.values()) {
        if (mSt.nfaStateIds.includes(hoveredState.id)) {
          minIds.add(mSt.id);
        }
      }
    }

    const summary = `Cross-Stage Correspondence: NFA {${Array.from(nfaIds)
      .map((q) => 'q' + q)
      .join(', ')}} ⟷ Powerset {${Array.from(powIds)
      .map((d) => 'D' + d)
      .join(', ')}} ⟷ Minimal {${Array.from(minIds)
      .map((m) => 'M' + m)
      .join(', ')}}`;

    return { nfaIds, powIds, minIds, summary };
  }, [compiled, hoveredState]);

  // SVGs for Pipeline Studio
  const pipelineSvgs = useMemo(() => {
    if (!compiled) return null;
    return {
      astSvg: generateAstSvg(compiled.ast),
      nfaSvg: generateNfaSvg(compiled.nfa, {
        activeStateIds: crossStageHighlights.nfaIds,
      }),
      powersetSvg: generateDfaSvg(compiled.powersetDfa, {
        activeStateIds: crossStageHighlights.powIds,
        showSubsets: true,
      }),
      minimalSvg: generateDfaSvg(compiled.minimalDfa, {
        activeStateIds: crossStageHighlights.minIds,
        showSubsets: true,
      }),
    };
  }, [compiled, crossStageHighlights]);

  // SVGs for Dual Debugger at current step
  const debuggerSvgs = useMemo(() => {
    if (!compiled || !simulation) return null;
    if (debugStepIdx === 0) {
      return {
        nfaSvg: generateNfaSvg(compiled.nfa, {
          activeStateIds: new Set(simulation.nfaInitialStates),
        }),
        minimalSvg: generateDfaSvg(compiled.minimalDfa, {
          activeStateIds: new Set([simulation.minimalInitialState]),
          showSubsets: true,
        }),
      };
    }

    const step = simulation.steps[debugStepIdx - 1];
    if (!step) return null;

    return {
      nfaSvg: generateNfaSvg(compiled.nfa, {
        directMoveIds: new Set(step.nfaDirectMove),
        epsilonAddedIds: new Set(step.nfaEpsilonAdditions),
      }),
      minimalSvg: generateDfaSvg(compiled.minimalDfa, {
        activeStateIds: step.minimalAfter !== null ? new Set([step.minimalAfter]) : new Set(),
        activeTransition:
          step.minimalBefore !== null && step.minimalAfter !== null
            ? { from: step.minimalBefore, to: step.minimalAfter }
            : null,
        showSubsets: true,
      }),
    };
  }, [compiled, simulation, debugStepIdx]);

  // Equivalence Prover Computation
  const equivalenceState = useMemo(() => {
    try {
      const proof = proveRegexEquivalence(equivRegex1, equivRegex2);
      return { proof, error: null };
    } catch (err: any) {
      return { proof: null, error: err?.message || 'Syntax error in comparison regex' };
    }
  }, [equivRegex1, equivRegex2]);

  // SIEM Master Automaton & Log Scan
  const masterSiem = useMemo(() => {
    return compileMasterSIEMAutomaton(siemRules);
  }, [siemRules]);

  const masterSiemSvg = useMemo(() => {
    return generateDfaSvg(masterSiem.minimizedMasterDfa, { showSubsets: false });
  }, [masterSiem]);

  const scannedLogs = useMemo(() => {
    const lines = logBatchText
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
    return lines.map((line, idx) => scanLogLineSinglePass(masterSiem, line, idx + 1));
  }, [masterSiem, logBatchText]);

  const selectedLogIncident = useMemo(() => {
    return (
      scannedLogs.find((inc) => inc.lineNumber === selectedIncidentLine) ||
      scannedLogs[0] ||
      null
    );
  }, [scannedLogs, selectedIncidentLine]);

  // Copy helper
  const copyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    window.setTimeout(() => setCopiedId(null), 1800);
  };

  // Export Content Generator
  const exportContent = useMemo(() => {
    if (!compiled || !simulation) return '';
    if (exportFormat === 'tikz') {
      return exportLatexTikz(compiled.minimalDfa, compiled.regex);
    }
    if (exportFormat === 'dot_dfa') {
      return exportGraphvizDot(compiled.nfa, compiled.minimalDfa, 'DFA', compiled.regex);
    }
    if (exportFormat === 'dot_nfa') {
      return exportGraphvizDot(compiled.nfa, compiled.minimalDfa, 'NFA', compiled.regex);
    }
    if (exportFormat === 'ascii_table') {
      return generateAsciiTransitionTable(compiled.nfa, compiled.minimalDfa);
    }
    return generateAsciiSimulationTrace(simulation);
  }, [compiled, simulation, exportFormat]);

  const handleAddSiemRule = (e: React.FormEvent) => {
    e.preventDefault();
    setSiemRuleError(null);
    if (!newRuleName.trim() || !newRulePattern.trim()) {
      setSiemRuleError('Provide both a signature name and a valid regular expression.');
      return;
    }
    try {
      compileRegexPipeline(newRulePattern.trim().toLowerCase());
      const nextId = `SEC-0${siemRules.length + 1}`;
      setSiemRules((prev) => [
        ...prev,
        {
          id: nextId,
          name: newRuleName.trim(),
          pattern: newRulePattern.trim(),
          threatLevel: newRuleThreat,
          category: newRuleCategory.trim() || 'Custom Rule',
          description: `User-defined deterministic signature (${newRulePattern.trim()}).`,
        },
      ]);
      setNewRuleName('');
      setNewRulePattern('');
    } catch (err: any) {
      setSiemRuleError(err?.message || 'Invalid regular expression pattern');
    }
  };

  const handleDownloadPythonModule = (filename: string, code: string) => {
    const blob = new Blob([code], { type: 'text/x-python;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleDownloadFullPythonBundle = () => {
    const bundle = UPGRADED_PYTHON_MODULES.map(
      (m) =>
        `# ============================================================================\n# FILE: finix_omega/${m.filename}\n# ${m.title}\n# ============================================================================\n\n${m.code}`
    ).join('\n\n');
    handleDownloadPythonModule('finix_omega_complete_suite.py', bundle);
  };

  const activeHopcroftStep =
    compiled?.hopcroftSteps[
      Math.min(hopcroftStepCursor, (compiled?.hopcroftSteps.length ?? 1) - 1)
    ] ?? null;

  const activePythonModule =
    UPGRADED_PYTHON_MODULES.find((m) => m.filename === selectedPythonFile) ||
    UPGRADED_PYTHON_MODULES[0];

  return (
    <div className="min-h-screen flex flex-col bg-[#090d16] text-slate-100">
      {/* =====================================================================
          STRICT 3-ZONE TOP BAR CONTRACT
          Zone 1: Brand Wordmark | Zone 2: 5 Nav Links | Zone 3: 1 Primary Action
         ===================================================================== */}
      <header className="flex items-center justify-between gap-8 px-6 py-3.5 border-b border-slate-800 bg-[#090d16]/95 sticky top-0 z-30 backdrop-blur">
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            setActiveTab('pipeline');
          }}
          className="text-lg font-bold tracking-tight text-slate-100 font-display whitespace-nowrap shrink-0"
        >
          FINIX Ω
        </a>

        <nav className="flex items-center gap-6 text-sm font-medium overflow-x-auto">
          <button
            type="button"
            onClick={() => setActiveTab('pipeline')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeTab === 'pipeline'
                ? 'border-sky-400 text-sky-300'
                : 'border-transparent text-slate-400 hover:text-slate-100'
            }`}
          >
            Pipeline Studio
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('debugger')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeTab === 'debugger'
                ? 'border-sky-400 text-sky-300'
                : 'border-transparent text-slate-400 hover:text-slate-100'
            }`}
          >
            Dual Debugger
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('prover')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeTab === 'prover'
                ? 'border-sky-400 text-sky-300'
                : 'border-transparent text-slate-400 hover:text-slate-100'
            }`}
          >
            Hopcroft &amp; Prover
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('siem')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeTab === 'siem'
                ? 'border-sky-400 text-sky-300'
                : 'border-transparent text-slate-400 hover:text-slate-100'
            }`}
          >
            SIEM Master DFA
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('python')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeTab === 'python'
                ? 'border-sky-400 text-sky-300'
                : 'border-transparent text-slate-400 hover:text-slate-100'
            }`}
          >
            Python Suite
          </button>
        </nav>

        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={() => setIsExportModalOpen(true)}
            className="px-4 py-2 text-xs font-semibold text-slate-950 bg-sky-400 hover:bg-sky-300 rounded-md transition-colors whitespace-nowrap shrink-0"
          >
            Export Artifacts
          </button>
        </div>
      </header>

      {/* =====================================================================
          GLOBAL COMPILER BAR (Shown on Pipeline, Debugger, and Hopcroft tabs)
         ===================================================================== */}
      {(activeTab === 'pipeline' || activeTab === 'debugger' || activeTab === 'prover') && (
        <section className="border-b border-slate-800 bg-slate-900/60 px-6 py-4">
          <div className="max-w-[1440px] mx-auto space-y-3">
            {/* Preset Selector Row */}
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-xs text-slate-400">
                <span className="font-semibold text-slate-300">Formal Grammar</span>
                <span aria-hidden="true">·</span>
                <span>Literals</span>
                <span aria-hidden="true">·</span>
                <span>Classes [a-z] \d \w</span>
                <span aria-hidden="true">·</span>
                <span>Quantifiers * + ? &#123;n,m&#125;</span>
                <span aria-hidden="true">·</span>
                <span>Intersection &amp;</span>
                <span aria-hidden="true">·</span>
                <span>Complement ~</span>
              </div>

              <div className="flex flex-wrap items-center gap-1.5">
                {COMPILER_PRESETS.map((preset) => (
                  <button
                    key={preset.id}
                    type="button"
                    onClick={() => {
                      setRegexInput(preset.regex);
                      setTestInput(preset.sampleAccept);
                    }}
                    className={`px-2.5 py-1 text-xs font-mono rounded transition-colors whitespace-nowrap shrink-0 ${
                      regexInput === preset.regex
                        ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40'
                        : 'bg-slate-800/80 text-slate-300 hover:bg-slate-800 border border-slate-700/60'
                    }`}
                  >
                    {preset.name}
                  </button>
                ))}
              </div>
            </div>

            {/* Primary Regex & Live Test Payload Inputs */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 items-stretch">
              <div className="lg:col-span-6 flex flex-col justify-between border border-slate-800 bg-slate-950 rounded-md px-3.5 py-2">
                <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                  <span>Regular Expression Pattern (r)</span>
                  {compiled && (
                    <span className="font-mono text-slate-400 tabular-nums">
                      Compiled in {compiled.compileTimeMs.toFixed(2)} ms · Postfix:{' '}
                      {compiled.postfixString.slice(0, 28)}
                      {compiled.postfixString.length > 28 ? '…' : ''}
                    </span>
                  )}
                </div>
                <input
                  type="text"
                  value={regexInput}
                  onChange={(e) => setRegexInput(e.target.value)}
                  spellCheck={false}
                  placeholder="Enter regular expression, e.g. (a|b)*abb or a{2,4}[0-9]+"
                  className="w-full bg-transparent font-mono text-base text-sky-300 focus:outline-none"
                />
              </div>

              <div className="lg:col-span-4 flex flex-col justify-between border border-slate-800 bg-slate-950 rounded-md px-3.5 py-2">
                <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
                  <span>Test Input String (w)</span>
                  <span className="font-mono tabular-nums">|w| = {testInput.length} chars</span>
                </div>
                <input
                  type="text"
                  value={testInput}
                  onChange={(e) => setTestInput(e.target.value)}
                  spellCheck={false}
                  placeholder="Enter string w to test..."
                  className="w-full bg-transparent font-mono text-base text-slate-100 focus:outline-none"
                />
              </div>

              <div className="lg:col-span-2 flex items-center justify-between border border-slate-800 bg-slate-950 rounded-md px-4 py-2">
                {compilationState.error ? (
                  <div className="flex items-center gap-2 text-rose-400 text-xs font-medium">
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    <span className="truncate">Syntax Error</span>
                  </div>
                ) : simulation?.isAccepted ? (
                  <div className="flex items-center gap-2.5">
                    <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                    <div>
                      <div className="text-xs font-bold text-emerald-400 tracking-wide">
                        ACCEPTED
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono tabular-nums">
                        w ∈ L(r) · {simulation.elapsedMs.toFixed(3)}ms
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center gap-2.5">
                    <XCircle className="w-5 h-5 text-rose-400 shrink-0" />
                    <div>
                      <div className="text-xs font-bold text-rose-400 tracking-wide">
                        REJECTED
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono tabular-nums">
                        w ∉ L(r) · {simulation?.elapsedMs.toFixed(3)}ms
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Syntax Error Banner or Compiler Telemetry & Minterm Strip */}
            {compilationState.error ? (
              <div className="border border-rose-500/40 bg-rose-950/30 text-rose-200 px-4 py-2.5 rounded-md text-xs font-mono flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{compilationState.error}</span>
              </div>
            ) : (
              compiled && (
                <div className="flex flex-wrap items-center justify-between gap-4 pt-1 text-xs text-slate-400">
                  <div className="flex flex-wrap items-center gap-2 font-mono tabular-nums">
                    <span className="text-slate-300">
                      Thompson ε-NFA: <strong className="text-sky-300">{compiled.nfa.states.size}</strong> states
                    </span>
                    <span aria-hidden="true">·</span>
                    <span className="text-slate-300">
                      Powerset DFA: <strong className="text-violet-300">{compiled.powersetDfa.states.size}</strong> states
                    </span>
                    <span aria-hidden="true">·</span>
                    <span className="text-slate-300">
                      Hopcroft Minimal DFA: <strong className="text-emerald-300">{compiled.minimalDfa.states.size}</strong> states
                    </span>
                    <span aria-hidden="true">·</span>
                    <span className="text-slate-300">
                      Minterm Classes (Σ/~): <strong className="text-amber-300">{compiled.minterms.length}</strong> partitions
                    </span>
                  </div>

                  <div className="flex items-center gap-2 font-mono text-xs">
                    <span className="text-slate-400">Disjoint Minterms:</span>
                    {compiled.minterms.map((mt) => (
                      <span
                        key={mt.id}
                        title={`Sample char: '${mt.sampleChar}' (${mt.chars.size} ASCII chars in partition)`}
                        className="text-sky-300"
                      >
                        M<sub>{mt.id}</sub>={mt.label}
                      </span>
                    ))}
                  </div>
                </div>
              )
            )}
          </div>
        </section>
      )}

      {/* =====================================================================
          MAIN WORKSPACE VIEWPORT
         ===================================================================== */}
      <main className="flex-1 max-w-[1440px] w-full mx-auto px-6 py-6">
        {/* -----------------------------------------------------------------
            WORKSPACE 1: SYNCHRONIZED 4-STAGE PIPELINE STUDIO
           ----------------------------------------------------------------- */}
        {activeTab === 'pipeline' && compiled && pipelineSvgs && (
          <div className="space-y-6">
            {/* Stage View Selector & Cross-Stage Correspondence Banner */}
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <h1 className="text-xl font-bold text-slate-100 font-display">
                  01. Synchronized 4-Stage Automaton Synthesis
                </h1>
                <p className="text-xs text-slate-400 mt-0.5">
                  Hover over any state node in the ε-NFA, Powerset DFA, or Minimal Quotient DFA to illuminate its exact Myhill-Nerode equivalence correspondence across all stages.
                </p>
              </div>

              <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg">
                {(
                  [
                    { id: 'all4', label: 'Synchronized 4-Stage Grid' },
                    { id: 'ast', label: '1. Algebraic AST' },
                    { id: 'nfa', label: '2. Thompson ε-NFA' },
                    { id: 'powerset', label: '3. Powerset DFA' },
                    { id: 'minimal', label: '4. Minimal DFA' },
                  ] as const
                ).map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => setPipelineStageMode(item.id)}
                    className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                      pipelineStageMode === item.id
                        ? 'bg-sky-500 text-slate-950 font-semibold'
                        : 'text-slate-400 hover:text-slate-100'
                    }`}
                  >
                    {item.label}
                  </button>
                ))}
              </div>
            </div>

            {crossStageHighlights.summary && (
              <div className="border border-amber-500/40 bg-amber-950/20 px-4 py-2 rounded-md text-xs font-mono text-amber-200 flex items-center justify-between">
                <span>{crossStageHighlights.summary}</span>
                <span className="text-amber-400/80">Live Cross-Stage Subset Projection</span>
              </div>
            )}

            {/* 4-Stage Grid or Single Focused Stage */}
            {pipelineStageMode === 'all4' ? (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                <InteractiveSvgCanvas
                  title="Stage 1 · Abstract Syntax Tree (AST)"
                  subtitle={`Postfix RPN: ${compiled.postfixString}`}
                  svgMarkup={pipelineSvgs.astSvg}
                  filenameSlug="stage1_ast"
                />
                <InteractiveSvgCanvas
                  title={`Stage 2 · Inductive Thompson ε-NFA (|Q| = ${compiled.nfa.states.size})`}
                  subtitle={`Start: q${compiled.nfa.startStateId} · Accept: q${compiled.nfa.acceptStateId} · Linear Bound ≤ 2|r|`}
                  svgMarkup={pipelineSvgs.nfaSvg}
                  filenameSlug="stage2_thompson_nfa"
                  onStateHover={setHoveredState}
                />
                <InteractiveSvgCanvas
                  title={`Stage 3 · Rabin-Scott Powerset DFA (|Q_D| = ${compiled.powersetDfa.states.size})`}
                  subtitle={`Determinized over ${compiled.minterms.length} Disjoint Minterm Equivalence Classes`}
                  svgMarkup={pipelineSvgs.powersetSvg}
                  filenameSlug="stage3_powerset_dfa"
                  onStateHover={setHoveredState}
                />
                <InteractiveSvgCanvas
                  title={`Stage 4 · Hopcroft Canonical Minimal DFA (|Q_M| = ${compiled.minimalDfa.states.size})`}
                  subtitle={`Reduced from ${compiled.powersetDfa.states.size} → ${compiled.minimalDfa.states.size} states via O(|Σ|·n log n) refinement`}
                  svgMarkup={pipelineSvgs.minimalSvg}
                  filenameSlug="stage4_minimal_dfa"
                  onStateHover={setHoveredState}
                />
              </div>
            ) : (
              <div className="grid grid-cols-1 gap-5">
                {pipelineStageMode === 'ast' && (
                  <InteractiveSvgCanvas
                    title="Stage 1 · Abstract Syntax Tree (AST)"
                    subtitle={`Postfix RPN: ${compiled.postfixString}`}
                    svgMarkup={pipelineSvgs.astSvg}
                    filenameSlug="stage1_ast"
                    minHeight="h-[500px]"
                  />
                )}
                {pipelineStageMode === 'nfa' && (
                  <InteractiveSvgCanvas
                    title={`Stage 2 · Inductive Thompson ε-NFA (|Q| = ${compiled.nfa.states.size})`}
                    subtitle={`Start: q${compiled.nfa.startStateId} · Accept: q${compiled.nfa.acceptStateId}`}
                    svgMarkup={pipelineSvgs.nfaSvg}
                    filenameSlug="stage2_thompson_nfa"
                    minHeight="h-[500px]"
                    onStateHover={setHoveredState}
                  />
                )}
                {pipelineStageMode === 'powerset' && (
                  <InteractiveSvgCanvas
                    title={`Stage 3 · Rabin-Scott Powerset DFA (|Q_D| = ${compiled.powersetDfa.states.size})`}
                    subtitle={`Subset Construction over Minterms Σ/~`}
                    svgMarkup={pipelineSvgs.powersetSvg}
                    filenameSlug="stage3_powerset_dfa"
                    minHeight="h-[500px]"
                    onStateHover={setHoveredState}
                  />
                )}
                {pipelineStageMode === 'minimal' && (
                  <InteractiveSvgCanvas
                    title={`Stage 4 · Hopcroft Canonical Minimal DFA (|Q_M| = ${compiled.minimalDfa.states.size})`}
                    subtitle={`Myhill-Nerode Quotient Automaton`}
                    svgMarkup={pipelineSvgs.minimalSvg}
                    filenameSlug="stage4_minimal_dfa"
                    minHeight="h-[500px]"
                    onStateHover={setHoveredState}
                  />
                )}
              </div>
            )}

            {/* Formal Transition Table & Static ReDoS Immunity Verification */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
              <div className="lg:col-span-8 border border-slate-800 bg-slate-900/90 rounded-lg p-5 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between gap-4 mb-3">
                    <h2 className="text-sm font-semibold text-slate-100">
                      Canonical Minimal DFA Transition Table δ(Mₖ, [c])
                    </h2>
                    <span className="text-xs text-slate-400 font-mono">
                      → Start · * Accept · ∅ Trap
                    </span>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse font-mono text-xs tabular-nums">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400">
                          <th className="py-2 pr-4">Quotient State</th>
                          <th className="py-2 px-4">Merged Powerset</th>
                          <th className="py-2 px-4">Constituent ε-NFA Subset</th>
                          {compiled.minimalDfa.alphabetLabels.map((lbl) => (
                            <th key={lbl} className="py-2 px-3 text-sky-300 text-center">
                              {lbl}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {Array.from(compiled.minimalDfa.states.values()).map((st) => (
                          <tr
                            key={st.id}
                            onMouseEnter={() => setHoveredState({ kind: 'MIN', id: st.id })}
                            onMouseLeave={() => setHoveredState(null)}
                            className="hover:bg-slate-800/50 transition-colors cursor-pointer"
                          >
                            <td className="py-2.5 pr-4 font-semibold text-slate-100">
                              <span className="text-sky-400 inline-block w-7">
                                {st.isStart && st.isAccept
                                  ? '→*'
                                  : st.isStart
                                  ? '→'
                                  : st.isAccept
                                  ? '*'
                                  : ''}
                              </span>
                              {st.name}
                            </td>
                            <td className="py-2.5 px-4 text-violet-300">
                              &#123;{st.powersetStateIds.map((d) => `D${d}`).join(', ')}&#125;
                            </td>
                            <td className="py-2.5 px-4 text-slate-400">
                              &#123;{st.nfaStateIds.map((q) => `q${q}`).join(', ')}&#125;
                            </td>
                            {compiled.minimalDfa.alphabetLabels.map((lbl) => {
                              const tgt = st.transitions.get(lbl);
                              return (
                                <td key={lbl} className="py-2.5 px-3 text-center">
                                  {tgt !== undefined ? (
                                    <span className="text-emerald-300 font-semibold">M{tgt}</span>
                                  ) : (
                                    <span className="text-slate-600">∅</span>
                                  )}
                                </td>
                              );
                            })}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>

              {/* Static ReDoS & Complexity Guarantee Card */}
              <div className="lg:col-span-4 border border-slate-800 bg-slate-900/90 rounded-lg p-5 flex flex-col justify-between space-y-4">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h2 className="text-sm font-semibold text-slate-100">
                      ReDoS &amp; Complexity Guarantee
                    </h2>
                    <span className="text-xs font-mono text-emerald-400 font-semibold">
                      {compiled.redosAnalysis.riskLevel}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {compiled.redosAnalysis.explanation}
                  </p>
                </div>

                <div className="space-y-2 pt-2 border-t border-slate-800 text-xs font-mono tabular-nums">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Backtracking Engine Risk:</span>
                    <span
                      className={
                        compiled.redosAnalysis.backtrackerRisk === 'CRITICAL'
                          ? 'text-rose-400 font-semibold'
                          : compiled.redosAnalysis.backtrackerRisk === 'MEDIUM'
                          ? 'text-amber-400 font-semibold'
                          : 'text-emerald-400'
                      }
                    >
                      {compiled.redosAnalysis.backtrackerRisk}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Quantifier Star-Height:</span>
                    <span className="text-slate-200">{compiled.redosAnalysis.starHeight}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">NFA Branching States:</span>
                    <span className="text-slate-200">
                      {compiled.redosAnalysis.nondeterministicBranching}
                    </span>
                  </div>
                </div>

                {compiled.redosAnalysis.evilPayloadSample && (
                  <button
                    type="button"
                    onClick={() => {
                      setTestInput(compiled.redosAnalysis.evilPayloadSample!);
                      setActiveTab('debugger');
                    }}
                    className="w-full py-2 px-3 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-sky-300 rounded border border-slate-700 transition-colors flex items-center justify-center gap-2"
                  >
                    <span>Test Adversarial Payload in Debugger</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            </div>
          </div>
        )}

        {/* -----------------------------------------------------------------
            WORKSPACE 2: LIVE DUAL-TRACE EXECUTION DEBUGGER
           ----------------------------------------------------------------- */}
        {activeTab === 'debugger' && compiled && simulation && debuggerSvgs && (
          <div className="space-y-6">
            {/* Debugger Transport & Character Ribbon */}
            <div className="border border-slate-800 bg-slate-900/90 rounded-lg p-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-4">
                <div>
                  <h1 className="text-xl font-bold text-slate-100 font-display">
                    02. Synchronized Dual-Track Step Debugger
                  </h1>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Scrub character-by-character to compare non-deterministic Thompson ε-NFA state sets (MOVE + ε-closure) against the single active state in Hopcroft&apos;s Minimal DFA.
                  </p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setIsPlaying(false);
                      setDebugStepIdx(0);
                    }}
                    className="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>Reset (Step 0)</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setIsPlaying(false);
                      setDebugStepIdx((s) => Math.max(0, s - 1));
                    }}
                    disabled={debugStepIdx === 0}
                    className="p-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 rounded transition-colors"
                    title="Previous Step"
                  >
                    <SkipBack className="w-4 h-4" />
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      if (debugStepIdx >= testInput.length) {
                        setDebugStepIdx(0);
                      }
                      setIsPlaying((p) => !p);
                    }}
                    className="px-4 py-1.5 text-xs font-semibold bg-sky-400 hover:bg-sky-300 text-slate-950 rounded transition-colors flex items-center gap-1.5 whitespace-nowrap shrink-0"
                  >
                    {isPlaying ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                    <span>{isPlaying ? 'Pause' : 'Auto-Step'}</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setIsPlaying(false);
                      setDebugStepIdx((s) => Math.min(testInput.length, s + 1));
                    }}
                    disabled={debugStepIdx >= testInput.length}
                    className="p-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 rounded transition-colors"
                    title="Next Step"
                  >
                    <SkipForward className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Interactive Input Tape */}
              <div className="flex items-center gap-1.5 overflow-x-auto py-2">
                <button
                  type="button"
                  onClick={() => {
                    setIsPlaying(false);
                    setDebugStepIdx(0);
                  }}
                  className={`px-3 py-2 rounded font-mono text-xs border transition-colors shrink-0 ${
                    debugStepIdx === 0
                      ? 'bg-amber-500/20 border-amber-400 text-amber-200 font-semibold'
                      : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  Step 0: ε-Init
                </button>
                {simulation.steps.map((st) => (
                  <button
                    key={st.stepIndex}
                    type="button"
                    onClick={() => {
                      setIsPlaying(false);
                      setDebugStepIdx(st.stepIndex);
                    }}
                    className={`px-3 py-2 rounded font-mono text-xs border transition-colors shrink-0 flex flex-col items-center min-w-[54px] ${
                      debugStepIdx === st.stepIndex
                        ? 'bg-amber-500/20 border-amber-400 text-amber-200 font-semibold'
                        : st.stepIndex < debugStepIdx
                        ? 'bg-slate-900 border-slate-700 text-slate-200'
                        : 'bg-slate-950 border-slate-800 text-slate-500 hover:text-slate-300'
                    }`}
                  >
                    <span className="text-[10px] text-slate-400">#{st.stepIndex}</span>
                    <span className="text-sm">&apos;{st.char}&apos;</span>
                  </button>
                ))}
              </div>

              {/* Current Step Equation Telemetry */}
              <div className="border-t border-slate-800 pt-3 flex flex-wrap items-center justify-between gap-4 text-xs font-mono tabular-nums">
                {debugStepIdx === 0 ? (
                  <div className="flex flex-wrap items-center gap-3">
                    <span className="text-sky-300">
                      Initial ε-Closure(q0) = &#123;
                      {simulation.nfaInitialStates.map((q) => `q${q}`).join(', ')}&#125;
                    </span>
                    <span aria-hidden="true">·</span>
                    <span className="text-amber-300">
                      Initial Minimal DFA State = M{simulation.minimalInitialState}
                    </span>
                  </div>
                ) : (
                  (() => {
                    const st = simulation.steps[debugStepIdx - 1];
                    return (
                      <div className="flex flex-wrap items-center gap-3">
                        <span className="text-slate-300">
                          Char <strong className="text-amber-300">&apos;{st.char}&apos;</strong> ∈ Minterm{' '}
                          <strong className="text-sky-300">{st.matchedMintermLabel}</strong>
                        </span>
                        <span aria-hidden="true">·</span>
                        <span className="text-sky-300">
                          Direct MOVE = &#123;
                          {st.nfaDirectMove.map((q) => `q${q}`).join(', ') || '∅'}&#125;
                        </span>
                        <span aria-hidden="true">·</span>
                        <span className="text-violet-300">
                          ε-Additions = &#123;
                          {st.nfaEpsilonAdditions.map((q) => `q${q}`).join(', ') || '∅'}&#125;
                        </span>
                        <span aria-hidden="true">·</span>
                        <span className="text-amber-300">
                          Minimal DFA: M{st.minimalBefore ?? '∅'} →{' '}
                          {st.minimalAfter !== null ? `M${st.minimalAfter}` : '∅ (Dead)'}
                        </span>
                      </div>
                    );
                  })()
                )}
              </div>
            </div>

            {/* Dual Side-by-Side Graph Canvases */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
              <InteractiveSvgCanvas
                title="Track A · Non-Deterministic Thompson ε-NFA Active Set"
                subtitle="Cyan = Direct MOVE(S, c) · Violet = ε-Closure Additions"
                svgMarkup={debuggerSvgs.nfaSvg}
                filenameSlug="debug_nfa_trace"
              />
              <InteractiveSvgCanvas
                title="Track B · Deterministic Hopcroft Minimal DFA Trajectory"
                subtitle="Gold Node & Edge = Single Active O(1) Deterministic State"
                svgMarkup={debuggerSvgs.minimalSvg}
                filenameSlug="debug_minimal_dfa_trace"
              />
            </div>

            {/* Complete Execution Trace Table */}
            <div className="border border-slate-800 bg-slate-900/90 rounded-lg p-5">
              <h2 className="text-sm font-semibold text-slate-100 mb-3">
                Step-by-Step Formal Execution Trace Table
              </h2>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse font-mono text-xs tabular-nums">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2 pr-3">Step</th>
                      <th className="py-2 px-3">Char</th>
                      <th className="py-2 px-3">Minterm</th>
                      <th className="py-2 px-3">NFA Active (Before)</th>
                      <th className="py-2 px-3 text-sky-300">Direct MOVE(S, c)</th>
                      <th className="py-2 px-3 text-violet-300">ε-Closure Additions</th>
                      <th className="py-2 px-3">NFA Active (After)</th>
                      <th className="py-2 px-3 text-amber-300">Minimal DFA</th>
                      <th className="py-2 pl-3">State Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {simulation.steps.map((st) => (
                      <tr
                        key={st.stepIndex}
                        onClick={() => {
                          setIsPlaying(false);
                          setDebugStepIdx(st.stepIndex);
                        }}
                        className={`cursor-pointer transition-colors ${
                          debugStepIdx === st.stepIndex
                            ? 'bg-amber-500/15 text-slate-100'
                            : 'hover:bg-slate-800/50 text-slate-300'
                        }`}
                      >
                        <td className="py-2 pr-3 font-semibold">#{st.stepIndex}</td>
                        <td className="py-2 px-3 text-amber-300">&apos;{st.char}&apos;</td>
                        <td className="py-2 px-3 text-sky-300">{st.matchedMintermLabel}</td>
                        <td className="py-2 px-3">
                          &#123;{st.nfaBefore.map((q) => `q${q}`).join(', ') || '∅'}&#125;
                        </td>
                        <td className="py-2 px-3 text-sky-300">
                          &#123;{st.nfaDirectMove.map((q) => `q${q}`).join(', ') || '∅'}&#125;
                        </td>
                        <td className="py-2 px-3 text-violet-300">
                          &#123;{st.nfaEpsilonAdditions.map((q) => `q${q}`).join(', ') || '∅'}&#125;
                        </td>
                        <td className="py-2 px-3">
                          &#123;{st.nfaAfter.map((q) => `q${q}`).join(', ') || '∅'}&#125;
                        </td>
                        <td className="py-2 px-3 text-amber-300 font-semibold">
                          M{st.minimalBefore ?? '∅'} →{' '}
                          {st.minimalAfter !== null ? `M${st.minimalAfter}` : '∅'}
                        </td>
                        <td className="py-2 pl-3">
                          {st.dfaAcceptsHere ? (
                            <span className="text-emerald-400 font-semibold">Accepting</span>
                          ) : st.minimalAfter === null ? (
                            <span className="text-rose-400">Dead / Trap</span>
                          ) : (
                            <span className="text-slate-400">Non-Accept</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* -----------------------------------------------------------------
            WORKSPACE 3: HOPCROFT REFINER & EQUIVALENCE WITNESS PROVER
           ----------------------------------------------------------------- */}
        {activeTab === 'prover' && compiled && (
          <div className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <h1 className="text-xl font-bold text-slate-100 font-display">
                  03. Hopcroft Partition Refiner &amp; Myhill-Nerode Theorem Prover
                </h1>
                <p className="text-xs text-slate-400 mt-0.5">
                  Inspect every partition split of Hopcroft&apos;s O(|Σ|·n log n) worklist algorithm or prove formal language equivalence L(r₁) ≡ L(r₂) with shortest counterexample synthesis.
                </p>
              </div>

              <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg">
                <button
                  type="button"
                  onClick={() => setProverSubMode('hopcroft')}
                  className={`px-3.5 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    proverSubMode === 'hopcroft'
                      ? 'bg-sky-500 text-slate-950 font-semibold'
                      : 'text-slate-400 hover:text-slate-100'
                  }`}
                >
                  Hopcroft Partition &amp; Myhill-Nerode Matrix
                </button>
                <button
                  type="button"
                  onClick={() => setProverSubMode('equivalence')}
                  className={`px-3.5 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    proverSubMode === 'equivalence'
                      ? 'bg-sky-500 text-slate-950 font-semibold'
                      : 'text-slate-400 hover:text-slate-100'
                  }`}
                >
                  Regex Equivalence &amp; Witness Prover (L₁ ⊕ L₂)
                </button>
              </div>
            </div>

            {proverSubMode === 'hopcroft' ? (
              <div className="space-y-6">
                {/* Hopcroft Step Scrubber */}
                <div className="border border-slate-800 bg-slate-900/90 rounded-lg p-5 space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-4">
                    <h2 className="text-sm font-semibold text-slate-100">
                      Hopcroft Worklist Partition Refinement Trace ({compiled.hopcroftSteps.length}{' '}
                      Refinement Stages)
                    </h2>
                    <div className="flex items-center gap-2">
                      {compiled.hopcroftSteps.map((st) => (
                        <button
                          key={st.stepIndex}
                          type="button"
                          onClick={() => setHopcroftStepCursor(st.stepIndex)}
                          className={`px-3 py-1 text-xs font-mono rounded border transition-colors ${
                            hopcroftStepCursor === st.stepIndex
                              ? 'bg-sky-500/20 border-sky-400 text-sky-300 font-semibold'
                              : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                          }`}
                        >
                          Step {st.stepIndex}
                        </button>
                      ))}
                    </div>
                  </div>

                  {activeHopcroftStep && (
                    <div className="space-y-4">
                      <p className="text-xs font-mono text-slate-200 bg-slate-950 border border-slate-800 p-3.5 rounded-md">
                        {activeHopcroftStep.explanation}
                      </p>

                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
                        <div className="border border-slate-800 bg-slate-950/70 p-3.5 rounded">
                          <div className="text-slate-400 mb-1">Active Splitter (S, c)</div>
                          <div className="text-amber-300 font-semibold">
                            S = &#123;{activeHopcroftStep.splitterBlock.map((d) => `D${d}`).join(', ')}
                            &#125; on &apos;{activeHopcroftStep.splitterSymbol}&apos;
                          </div>
                        </div>
                        <div className="border border-slate-800 bg-slate-950/70 p-3.5 rounded">
                          <div className="text-slate-400 mb-1">Inverse Preimage X = δ⁻¹(S, c)</div>
                          <div className="text-sky-300 font-semibold">
                            &#123;{activeHopcroftStep.preimage.map((d) => `D${d}`).join(', ')}&#125;
                          </div>
                        </div>
                        <div className="border border-slate-800 bg-slate-950/70 p-3.5 rounded">
                          <div className="text-slate-400 mb-1">Block Split Y → (Y ∩ X, Y \ X)</div>
                          <div className="text-emerald-300 font-semibold">
                            &#123;{activeHopcroftStep.intersectionPart.map((d) => `D${d}`).join(', ')}
                            &#125; ∪ &#123;
                            {activeHopcroftStep.differencePart.map((d) => `D${d}`).join(', ')}&#125;
                          </div>
                        </div>
                      </div>

                      <div>
                        <div className="text-xs text-slate-400 mb-2">
                          Equivalence Classes After Step {activeHopcroftStep.stepIndex}:
                        </div>
                        <div className="flex flex-wrap gap-2.5">
                          {activeHopcroftStep.partitionsAfter.map((block, bIdx) => (
                            <div
                              key={bIdx}
                              className="px-3.5 py-2 rounded border border-slate-700 bg-slate-950 font-mono text-xs flex items-center gap-2"
                            >
                              <span className="text-slate-400">Block P_{bIdx}:</span>
                              <span className="text-sky-300 font-semibold">
                                &#123;{block.map((d) => `D${d}`).join(', ')}&#125;
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* Myhill-Nerode Pairwise Distinguishability Table */}
                <div className="border border-slate-800 bg-slate-900/90 rounded-lg p-5">
                  <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
                    <div>
                      <h2 className="text-sm font-semibold text-slate-100">
                        Myhill-Nerode Pairwise Distinguishability &amp; Shortest Suffix Table
                      </h2>
                      <p className="text-xs text-slate-400">
                        For every pair of Powerset DFA states (Dᵢ, Dⱼ), displays the shortest distinguishing suffix string w such that δ̂(Dᵢ, w) ∈ F ⟺ δ̂(Dⱼ, w) ∉ F, or proves Dᵢ ≡ Dⱼ.
                      </p>
                    </div>
                  </div>

                  {compiled.myhillNerodeTable.length === 0 ? (
                    <p className="text-xs text-slate-400 font-mono">
                      Powerset DFA has only 1 state (D0); no state pairs to distinguish.
                    </p>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left border-collapse font-mono text-xs tabular-nums">
                        <thead>
                          <tr className="border-b border-slate-800 text-slate-400">
                            <th className="py-2 pr-4">State Pair</th>
                            <th className="py-2 px-4">Myhill-Nerode Relation</th>
                            <th className="py-2 px-4">Shortest Distinguishing Suffix (w)</th>
                            <th className="py-2 pl-4">Discovery Round</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60">
                          {compiled.myhillNerodeTable.map((cell) => (
                            <tr
                              key={`${cell.stateA}_${cell.stateB}`}
                              className="hover:bg-slate-800/50 transition-colors"
                            >
                              <td className="py-2 pr-4 font-semibold text-slate-200">
                                (D{cell.stateA}, D{cell.stateB})
                              </td>
                              <td className="py-2 px-4">
                                {cell.distinguishable ? (
                                  <span className="text-amber-300">
                                    D{cell.stateA} ≢ D{cell.stateB} (Distinguishable)
                                  </span>
                                ) : (
                                  <span className="text-emerald-400 font-semibold">
                                    D{cell.stateA} ≡ D{cell.stateB} (Merged in Minimal DFA)
                                  </span>
                                )}
                              </td>
                              <td className="py-2 px-4 text-sky-300">
                                {cell.distinguishable
                                  ? cell.witnessSuffix === 'ε'
                                    ? 'ε (0-step: Accept vs Non-Accept)'
                                    : `"${cell.witnessSuffix}"`
                                  : 'None (Indistinguishable ∀w ∈ Σ*)'}
                              </td>
                              <td className="py-2 pl-4 text-slate-400">
                                {cell.distinguishable ? `Round ${cell.roundIdentified}` : 'Merged'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              /* Sub-mode B: Automated Equivalence & Shortest Counterexample Witness Prover */
              <div className="space-y-6">
                <div className="border border-slate-800 bg-slate-900/90 rounded-lg p-5 space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-slate-300">
                      Algebraic Identity &amp; Counterexample Presets:
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {EQUIVALENCE_PRESETS.map((p) => (
                        <button
                          key={p.name}
                          type="button"
                          onClick={() => {
                            setEquivRegex1(p.r1);
                            setEquivRegex2(p.r2);
                          }}
                          className="px-2.5 py-1 text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700 transition-colors"
                        >
                          {p.name}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="border border-slate-800 bg-slate-950 rounded-md px-3.5 py-2.5">
                      <div className="text-xs text-slate-400 mb-1">Regular Expression r₁</div>
                      <input
                        type="text"
                        value={equivRegex1}
                        onChange={(e) => setEquivRegex1(e.target.value)}
                        spellCheck={false}
                        className="w-full bg-transparent font-mono text-base text-sky-300 focus:outline-none"
                      />
                    </div>
                    <div className="border border-slate-800 bg-slate-950 rounded-md px-3.5 py-2.5">
                      <div className="text-xs text-slate-400 mb-1">Regular Expression r₂</div>
                      <input
                        type="text"
                        value={equivRegex2}
                        onChange={(e) => setEquivRegex2(e.target.value)}
                        spellCheck={false}
                        className="w-full bg-transparent font-mono text-base text-violet-300 focus:outline-none"
                      />
                    </div>
                  </div>

                  {equivalenceState.error ? (
                    <div className="border border-rose-500/40 bg-rose-950/30 text-rose-200 px-4 py-2.5 rounded text-xs font-mono">
                      {equivalenceState.error}
                    </div>
                  ) : (
                    equivalenceState.proof && (
                      <div className="space-y-4 pt-2">
                        {/* Verdict Banner */}
                        <div
                          className={`p-4 rounded-lg border flex flex-wrap items-center justify-between gap-4 ${
                            equivalenceState.proof.isEquivalent
                              ? 'border-emerald-500/40 bg-emerald-950/20'
                              : 'border-amber-500/40 bg-amber-950/20'
                          }`}
                        >
                          <div className="flex items-center gap-3">
                            {equivalenceState.proof.isEquivalent ? (
                              <CheckCircle2 className="w-6 h-6 text-emerald-400 shrink-0" />
                            ) : (
                              <GitCompare className="w-6 h-6 text-amber-400 shrink-0" />
                            )}
                            <div>
                              <div className="text-sm font-bold text-slate-100 font-mono">
                                {equivalenceState.proof.relationSummary}
                              </div>
                              <div className="text-xs text-slate-300 mt-0.5">
                                {equivalenceState.proof.isEquivalent
                                  ? `Formal Proof Complete: L('${equivRegex1}') and L('${equivRegex2}') reduce to isomorphic ${equivalenceState.proof.compiled1.minimalDfa.states.size}-state Minimal DFAs.`
                                  : `Symmetric Difference L(r₁) ⊕ L(r₂) ≠ ∅. Shortest counterexample witnesses synthesized via Product BFS:`}
                              </div>
                            </div>
                          </div>

                          {/* Counterexample Witness Cards */}
                          {!equivalenceState.proof.isEquivalent && (
                            <div className="flex flex-wrap items-center gap-3">
                              {equivalenceState.proof.witness1Minus2 !== null && (
                                <button
                                  type="button"
                                  onClick={() => {
                                    setRegexInput(equivRegex1);
                                    setTestInput(equivalenceState.proof!.witness1Minus2!);
                                    setActiveTab('debugger');
                                  }}
                                  className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded text-xs font-mono text-sky-300 flex items-center gap-2"
                                >
                                  <span>
                                    w ∈ L₁ \ L₂:{' '}
                                    <strong>
                                      {equivalenceState.proof.witness1Minus2 === ''
                                        ? 'ε'
                                        : `"${equivalenceState.proof.witness1Minus2}"`}
                                    </strong>
                                  </span>
                                  <ArrowRight className="w-3.5 h-3.5" />
                                </button>
                              )}
                              {equivalenceState.proof.witness2Minus1 !== null && (
                                <button
                                  type="button"
                                  onClick={() => {
                                    setRegexInput(equivRegex2);
                                    setTestInput(equivalenceState.proof!.witness2Minus1!);
                                    setActiveTab('debugger');
                                  }}
                                  className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded text-xs font-mono text-violet-300 flex items-center gap-2"
                                >
                                  <span>
                                    w ∈ L₂ \ L₁:{' '}
                                    <strong>
                                      {equivalenceState.proof.witness2Minus1 === ''
                                        ? 'ε'
                                        : `"${equivalenceState.proof.witness2Minus1}"`}
                                    </strong>
                                  </span>
                                  <ArrowRight className="w-3.5 h-3.5" />
                                </button>
                              )}
                            </div>
                          )}
                        </div>

                        {/* Formal Proof Steps */}
                        <div className="border border-slate-800 bg-slate-950 p-4 rounded-md space-y-1.5 font-mono text-xs text-slate-300">
                          {equivalenceState.proof.formalProofSteps.map((line, idx) => (
                            <div key={idx}>{line}</div>
                          ))}
                        </div>

                        {/* Side-by-Side Minimal DFAs for r1 and r2 */}
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                          <InteractiveSvgCanvas
                            title={`Minimal DFA M₁ for r₁ = ${equivRegex1}`}
                            subtitle={`|Q₁| = ${equivalenceState.proof.compiled1.minimalDfa.states.size} canonical states`}
                            svgMarkup={generateDfaSvg(equivalenceState.proof.compiled1.minimalDfa)}
                            filenameSlug="equiv_m1"
                          />
                          <InteractiveSvgCanvas
                            title={`Minimal DFA M₂ for r₂ = ${equivRegex2}`}
                            subtitle={`|Q₂| = ${equivalenceState.proof.compiled2.minimalDfa.states.size} canonical states`}
                            svgMarkup={generateDfaSvg(equivalenceState.proof.compiled2.minimalDfa)}
                            filenameSlug="equiv_m2"
                          />
                        </div>
                      </div>
                    )
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* -----------------------------------------------------------------
            WORKSPACE 4: SINGLE-PASS O(|w|) MASTER DFA SIEM LOG FORENSICS
           ----------------------------------------------------------------- */}
        {activeTab === 'siem' && (
          <div className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <h1 className="text-xl font-bold text-slate-100 font-display">
                  04. True Single-Pass O(|w|) Multi-Output Master DFA SIEM Engine
                </h1>
                <p className="text-xs text-slate-400 mt-0.5">
                  Compiles all {masterSiem.rules.length} security signatures into a single Moore-minimized Master Automaton ({masterSiem.minimizedMasterDfa.states.size} states over {masterSiem.unifiedMinterms.length} unified minterms) that inspects log lines in one pass.
                </p>
              </div>

              <div className="flex items-center gap-4 text-xs font-mono tabular-nums text-slate-300">
                <span>
                  Signatures: <strong className="text-sky-300">{masterSiem.rules.length}</strong>
                </span>
                <span aria-hidden="true">·</span>
                <span>
                  Master DFA States:{' '}
                  <strong className="text-emerald-300">
                    {masterSiem.minimizedMasterDfa.states.size}
                  </strong>
                </span>
                <span aria-hidden="true">·</span>
                <span>
                  Flagged Incidents:{' '}
                  <strong className="text-rose-400">
                    {scannedLogs.filter((l) => l.matchedRules.length > 0).length}
                  </strong>{' '}
                  / {scannedLogs.length}
                </span>
              </div>
            </div>

            {/* Master DFA Graph & Signature Catalog */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
              <div className="lg:col-span-7">
                <InteractiveSvgCanvas
                  title={`Unified Multi-Rule Master DFA (|Q_Master| = ${masterSiem.minimizedMasterDfa.states.size} Moore States)`}
                  subtitle="Red [SEC-XX] annotations indicate accepting states tagged with exact triggered rule IDs"
                  svgMarkup={masterSiemSvg}
                  filenameSlug="master_siem_dfa"
                  minHeight="h-[360px]"
                />
              </div>

              <div className="lg:col-span-5 border border-slate-800 bg-slate-900/90 rounded-lg p-4 flex flex-col justify-between space-y-4">
                <div className="space-y-2">
                  <h2 className="text-sm font-semibold text-slate-100">
                    Active Security Signature Catalog ({siemRules.length} Rules)
                  </h2>
                  <div className="max-h-[210px] overflow-y-auto divide-y divide-slate-800/70 pr-1">
                    {masterSiem.rules.map((r) => (
                      <div key={r.id} className="py-2 flex items-start justify-between gap-2 text-xs">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-sky-300">{r.id}</span>
                            <span aria-hidden="true">·</span>
                            <span className="font-medium text-slate-200 truncate">{r.name}</span>
                          </div>
                          <div className="font-mono text-[11px] text-slate-400 truncate mt-0.5">
                            {r.pattern} ({r.stateCount} DFA states)
                          </div>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <span
                            className={`font-mono text-[11px] font-semibold ${
                              r.threatLevel === 'CRITICAL'
                                ? 'text-rose-400'
                                : r.threatLevel === 'HIGH'
                                ? 'text-amber-400'
                                : 'text-sky-300'
                            }`}
                          >
                            {r.threatLevel}
                          </span>
                          {siemRules.length > 1 && (
                            <button
                              type="button"
                              onClick={() =>
                                setSiemRules((prev) => prev.filter((item) => item.id !== r.id))
                              }
                              className="text-slate-500 hover:text-rose-400 transition-colors"
                              title="Remove signature"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Add Custom SIEM Rule Form */}
                <form onSubmit={handleAddSiemRule} className="pt-3 border-t border-slate-800 space-y-2">
                  <div className="text-xs font-semibold text-slate-300">
                    Compile Additional Signature into Master DFA
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    <input
                      type="text"
                      value={newRuleName}
                      onChange={(e) => setNewRuleName(e.target.value)}
                      placeholder="Rule name (e.g. Log4j JNDI)"
                      className="px-2.5 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded text-slate-200 focus:outline-none focus:border-sky-500"
                    />
                    <input
                      type="text"
                      value={newRulePattern}
                      onChange={(e) => setNewRulePattern(e.target.value)}
                      placeholder="Regex (e.g. .*jndi:ldap.*)"
                      className="px-2.5 py-1.5 text-xs font-mono bg-slate-950 border border-slate-800 rounded text-sky-300 focus:outline-none focus:border-sky-500"
                    />
                  </div>
                  {siemRuleError && (
                    <div className="text-[11px] text-rose-400 font-mono">{siemRuleError}</div>
                  )}
                  <div className="flex items-center justify-between gap-2">
                    <select
                      value={newRuleThreat}
                      onChange={(e) =>
                        setNewRuleThreat(e.target.value as SIEMRule['threatLevel'])
                      }
                      className="px-2.5 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded text-slate-300"
                    >
                      <option value="CRITICAL">CRITICAL</option>
                      <option value="HIGH">HIGH</option>
                      <option value="MEDIUM">MEDIUM</option>
                    </select>
                    <button
                      type="submit"
                      className="px-3 py-1.5 text-xs font-semibold bg-sky-400 hover:bg-sky-300 text-slate-950 rounded transition-colors flex items-center gap-1.5"
                    >
                      <Plus className="w-3.5 h-3.5" />
                      <span>Add &amp; Recompile Master DFA</span>
                    </button>
                  </div>
                </form>
              </div>
            </div>

            {/* Live Apache/Nginx Log Stream Input & Single-Pass Forensics Table */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
              <div className="lg:col-span-5 border border-slate-800 bg-slate-900/90 rounded-lg p-4 flex flex-col space-y-2">
                <div className="flex items-center justify-between">
                  <h2 className="text-sm font-semibold text-slate-100">
                    Live HTTP / Nginx Access Log Stream
                  </h2>
                  <button
                    type="button"
                    onClick={() => setLogBatchText(SAMPLE_ACCESS_LOGS.join('\n'))}
                    className="text-xs text-sky-400 hover:underline"
                  >
                    Reset Sample Stream
                  </button>
                </div>
                <textarea
                  value={logBatchText}
                  onChange={(e) => setLogBatchText(e.target.value)}
                  rows={10}
                  spellCheck={false}
                  className="w-full flex-1 bg-slate-950 border border-slate-800 rounded p-3 font-mono text-xs text-slate-300 focus:outline-none focus:border-sky-500"
                />
              </div>

              <div className="lg:col-span-7 border border-slate-800 bg-slate-900/90 rounded-lg p-4 space-y-4">
                <h2 className="text-sm font-semibold text-slate-100">
                  Single-Pass Deterministic Inspection Results (Click Row to Inspect Trajectory)
                </h2>
                <div className="overflow-x-auto max-h-[260px]">
                  <table className="w-full text-left border-collapse font-mono text-xs tabular-nums">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400">
                        <th className="py-2 pr-3">Line</th>
                        <th className="py-2 px-3">Source IP</th>
                        <th className="py-2 px-3">Inspect URI / Payload</th>
                        <th className="py-2 px-3">Triggered Rules</th>
                        <th className="py-2 pl-3">Verdict</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {scannedLogs.map((rec) => (
                        <tr
                          key={rec.lineNumber}
                          onClick={() => setSelectedIncidentLine(rec.lineNumber)}
                          className={`cursor-pointer transition-colors ${
                            selectedLogIncident?.lineNumber === rec.lineNumber
                              ? 'bg-sky-500/15 text-slate-100'
                              : 'hover:bg-slate-800/50 text-slate-300'
                          }`}
                        >
                          <td className="py-2 pr-3 font-semibold">#{rec.lineNumber}</td>
                          <td className="py-2 px-3 text-slate-400">{rec.ip}</td>
                          <td className="py-2 px-3 max-w-[240px] truncate text-slate-200">
                            {rec.uri}
                          </td>
                          <td className="py-2 px-3">
                            {rec.matchedRules.length > 0 ? (
                              <span className="text-rose-400 font-semibold">
                                {rec.matchedRules.map((r) => r.id).join(', ')}
                              </span>
                            ) : (
                              <span className="text-slate-500">—</span>
                            )}
                          </td>
                          <td className="py-2 pl-3">
                            {rec.highestThreat === 'SAFE' ? (
                              <span className="text-emerald-400">CLEAN</span>
                            ) : (
                              <span className="text-rose-400 font-bold">{rec.highestThreat}</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* Selected Line O(|w|) Master DFA State Trajectory */}
                {selectedLogIncident && (
                  <div className="border-t border-slate-800 pt-3 space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                      <span className="font-semibold text-slate-200">
                        Line #{selectedLogIncident.lineNumber} Single-Pass Master DFA State Trajectory:
                      </span>
                      <span className="font-mono text-slate-400">
                        {selectedLogIncident.masterStateTrajectory.length} character transitions · 0 Backtracking
                      </span>
                    </div>
                    <div className="flex items-center gap-1 overflow-x-auto py-1.5 font-mono text-[11px]">
                      {selectedLogIncident.masterStateTrajectory.slice(0, 48).map((hop) => (
                        <div
                          key={hop.index}
                          className={`px-2 py-1 rounded border shrink-0 ${
                            hop.triggeredRuleIdsAtStep.length > 0
                              ? 'border-rose-500/50 bg-rose-950/30 text-rose-200'
                              : 'border-slate-800 bg-slate-950 text-slate-300'
                          }`}
                        >
                          <div className="text-[10px] text-slate-400">&apos;{hop.char}&apos;</div>
                          <div className="font-semibold text-sky-300">{hop.toMasterState}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* -----------------------------------------------------------------
            WORKSPACE 5: UPGRADED PYTHON 3.12+ CODEBASE & EXPORTER
           ----------------------------------------------------------------- */}
        {activeTab === 'python' && (
          <div className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <h1 className="text-xl font-bold text-slate-100 font-display">
                  05. Upgraded Python 3.12+ Architecture Suite (FINIX Ω)
                </h1>
                <p className="text-xs text-slate-400 mt-0.5">
                  Inspect, compare, copy, or download the complete 9-module Python package featuring Minterm Partitioning, {`{n,m}`} Quantifiers, Witness Synthesis, and the fixed O(|w|) Multi-Tag Master DFA.
                </p>
              </div>

              <button
                type="button"
                onClick={handleDownloadFullPythonBundle}
                className="px-4 py-2 text-xs font-semibold bg-sky-400 hover:bg-sky-300 text-slate-950 rounded-md transition-colors flex items-center gap-2 whitespace-nowrap shrink-0"
              >
                <Download className="w-4 h-4" />
                <span>Download Complete Python Suite (.py)</span>
              </button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
              {/* Left Module Selector Sidebar */}
              <div className="lg:col-span-3 border border-slate-800 bg-slate-900/90 rounded-lg divide-y divide-slate-800">
                {UPGRADED_PYTHON_MODULES.map((mod) => (
                  <button
                    key={mod.filename}
                    type="button"
                    onClick={() => setSelectedPythonFile(mod.filename)}
                    className={`w-full text-left px-4 py-3 transition-colors flex items-center justify-between gap-2 ${
                      selectedPythonFile === mod.filename
                        ? 'bg-sky-500/15 text-sky-300'
                        : 'text-slate-300 hover:bg-slate-800/60'
                    }`}
                  >
                    <div className="min-w-0">
                      <div className="font-mono text-xs font-semibold truncate">{mod.filename}</div>
                      <div className="text-[11px] text-slate-400 truncate mt-0.5">{mod.title}</div>
                    </div>
                    <span className="font-mono text-[11px] text-slate-400 tabular-nums shrink-0">
                      {mod.linesOfCode}L
                    </span>
                  </button>
                ))}
              </div>

              {/* Right Code & Architectural Diff Panel */}
              <div className="lg:col-span-9 space-y-4">
                {/* Original vs FINIX Ω Upgrade Comparison Card */}
                <div className="border border-slate-800 bg-slate-900/90 rounded-lg p-5 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <h2 className="text-base font-bold text-slate-100 font-mono">
                        finix_omega/{activePythonModule.filename}
                      </h2>
                      <p className="text-xs text-slate-400">{activePythonModule.title}</p>
                    </div>
                    <span className="text-xs font-mono text-emerald-400">
                      {activePythonModule.complexityGuarantee}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 text-xs">
                    <div className="border border-rose-500/30 bg-rose-950/15 rounded p-3.5 space-y-1">
                      <div className="font-semibold text-rose-300">
                        Original Script Limitation (FINIX v1)
                      </div>
                      <p className="text-slate-300 leading-relaxed">
                        {activePythonModule.originalLimitation}
                      </p>
                    </div>
                    <div className="border border-emerald-500/30 bg-emerald-950/15 rounded p-3.5 space-y-1">
                      <div className="font-semibold text-emerald-300">
                        FINIX Ω Generational Upgrade
                      </div>
                      <p className="text-slate-300 leading-relaxed">
                        {activePythonModule.generationalUpgrade}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Python Source Viewer */}
                <div className="border border-slate-800 bg-slate-950 rounded-lg overflow-hidden">
                  <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-800 bg-slate-900">
                    <span className="font-mono text-xs text-slate-300">
                      {activePythonModule.filename} · Python 3.12+ Strict Type Annotations
                    </span>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() =>
                          copyText(activePythonModule.code, activePythonModule.filename)
                        }
                        className="px-3 py-1 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded transition-colors flex items-center gap-1.5"
                      >
                        {copiedId === activePythonModule.filename ? (
                          <>
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                            <span>Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5" />
                            <span>Copy Module</span>
                          </>
                        )}
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          handleDownloadPythonModule(
                            activePythonModule.filename,
                            activePythonModule.code
                          )
                        }
                        className="px-3 py-1 text-xs font-medium bg-sky-500/20 hover:bg-sky-500/30 text-sky-300 border border-sky-500/40 rounded transition-colors flex items-center gap-1.5"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>Download {activePythonModule.filename}</span>
                      </button>
                    </div>
                  </div>
                  <pre className="p-4 text-xs font-mono text-slate-200 overflow-x-auto max-h-[540px] leading-relaxed">
                    <code>{activePythonModule.code}</code>
                  </pre>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* =====================================================================
          EXPORT ARTIFACTS MODAL (LaTeX TikZ, Graphviz DOT, Formal ASCII)
         ===================================================================== */}
      {isExportModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="w-full max-w-3xl border border-slate-800 bg-slate-900 rounded-lg overflow-hidden shadow-2xl">
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-800 bg-slate-950">
              <div>
                <h2 className="text-sm font-bold text-slate-100 font-display">
                  Academic &amp; Engineering Artifact Exporter
                </h2>
                <p className="text-xs text-slate-400">
                  Export publication-ready LaTeX TikZ, Graphviz DOT, or TOC ASCII Tables for pattern:{' '}
                  <code className="text-sky-300">{regexInput}</code>
                </p>
              </div>
              <button
                type="button"
                onClick={() => setIsExportModalOpen(false)}
                className="p-1.5 text-slate-400 hover:text-slate-100 rounded"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap gap-1.5">
                  {(
                    [
                      { id: 'tikz', label: 'LaTeX TikZ (IEEE/ACM Paper)' },
                      { id: 'dot_dfa', label: 'Graphviz DOT (Minimal DFA)' },
                      { id: 'dot_nfa', label: 'Graphviz DOT (Thompson ε-NFA)' },
                      { id: 'ascii_table', label: 'Formal ASCII Transition Table' },
                      { id: 'ascii_trace', label: 'ASCII Simulation Trace' },
                    ] as const
                  ).map((tab) => (
                    <button
                      key={tab.id}
                      type="button"
                      onClick={() => setExportFormat(tab.id)}
                      className={`px-3 py-1.5 text-xs font-medium rounded transition-colors ${
                        exportFormat === tab.id
                          ? 'bg-sky-400 text-slate-950 font-semibold'
                          : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                      }`}
                    >
                      {tab.label}
                    </button>
                  ))}
                </div>

                <button
                  type="button"
                  onClick={() => copyText(exportContent, 'modal_export')}
                  className="px-3.5 py-1.5 text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-sky-300 rounded border border-slate-700 flex items-center gap-1.5"
                >
                  {copiedId === 'modal_export' ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Copied to Clipboard</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy Artifact</span>
                    </>
                  )}
                </button>
              </div>

              <pre className="p-4 bg-slate-950 border border-slate-800 rounded font-mono text-xs text-slate-200 overflow-x-auto max-h-[380px] leading-relaxed">
                <code>{exportContent}</code>
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
