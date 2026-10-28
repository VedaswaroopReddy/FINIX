/**
 * automataEngine.ts: FINIX Ω Formal Automata Compiler, Minterm Partitioner,
 * Hopcroft Step-by-Step Refiner, Myhill-Nerode Prover, and Counterexample Witness Synthesizer.
 */

export const EPSILON = 'ε';
export const WILDCARD = 'Σ';

export const PRINTABLE_ASCII: string[] = Array.from(
  { length: 95 },
  (_, i) => String.fromCharCode(i + 32)
);

const DIGITS = new Set('0123456789'.split(''));
const WORD_CHARS = new Set(
  'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'.split('')
);
const WHITESPACE = new Set([' ', '\t']);

export const SHORTHANDS: Record<string, { chars: Set<string>; display: string }> = {
  d: { chars: DIGITS, display: '\\d' },
  D: {
    chars: new Set(PRINTABLE_ASCII.filter((c) => !DIGITS.has(c))),
    display: '\\D',
  },
  w: { chars: WORD_CHARS, display: '\\w' },
  W: {
    chars: new Set(PRINTABLE_ASCII.filter((c) => !WORD_CHARS.has(c))),
    display: '\\W',
  },
  s: { chars: WHITESPACE, display: '\\s' },
  S: {
    chars: new Set(PRINTABLE_ASCII.filter((c) => !WHITESPACE.has(c))),
    display: '\\S',
  },
};

export enum TokenType {
  CHAR = 'CHAR',
  ANY = 'ANY',
  CHAR_CLASS = 'CHAR_CLASS',
  STAR = 'STAR',
  PLUS = 'PLUS',
  OPTIONAL = 'OPTIONAL',
  QUANTIFIER = 'QUANTIFIER',
  COMPLEMENT = 'COMPLEMENT',
  CONCAT = 'CONCAT',
  INTERSECT = 'INTERSECT',
  UNION = 'UNION',
  LPAREN = 'LPAREN',
  RPAREN = 'RPAREN',
}

export interface Token {
  type: TokenType;
  value: string;
  pos: number;
  escaped?: boolean;
  charset?: Set<string>;
  minRepeat?: number;
  maxRepeat?: number | null; // null = unbounded {n,}
}

export interface ASTNode {
  id: string;
  kind:
    | 'Literal'
    | 'Wildcard'
    | 'CharClass'
    | 'Concat'
    | 'Union'
    | 'Intersect'
    | 'Star'
    | 'Plus'
    | 'Optional'
    | 'Repeat'
    | 'Complement';
  label: string;
  char?: string;
  charset?: Set<string>;
  minRepeat?: number;
  maxRepeat?: number | null;
  children: ASTNode[];
}

export interface MintermClass {
  id: number;
  label: string;
  sampleChar: string;
  chars: Set<string>;
  isCatchAll: boolean;
}

export interface NFATransition {
  symbolKind: 'EPSILON' | 'CHAR' | 'ANY' | 'CHARSET';
  display: string;
  char?: string;
  charset?: Set<string>;
  targetId: number;
}

export interface NFAStateData {
  id: number;
  isStart: boolean;
  isAccept: boolean;
  transitions: NFATransition[];
}

export interface CompiledNFA {
  startStateId: number;
  acceptStateId: number;
  states: Map<number, NFAStateData>;
  alphabet: string[];
  hasWildcard: boolean;
}

export interface DFAStateData {
  id: number;
  name: string; // D0, D1 or M0, M1
  isStart: boolean;
  isAccept: boolean;
  nfaStateIds: number[];
  powersetStateIds: number[]; // For Minimal DFA: which D_i states merged into M_k
  transitions: Map<string, number>; // minterm label -> target state id
  charTransitions: Map<string, number>; // single char -> target state id
  matchedRules?: string[];
}

export interface CompiledDFA {
  kind: 'POWERSET' | 'MINIMAL';
  startStateId: number;
  states: Map<number, DFAStateData>;
  minterms: MintermClass[];
  alphabetLabels: string[];
}

export interface HopcroftSplitStep {
  stepIndex: number;
  splitterBlock: number[];
  splitterSymbol: string;
  preimage: number[];
  targetBlockBefore: number[];
  intersectionPart: number[];
  differencePart: number[];
  partitionsAfter: number[][];
  worklistSizeAfter: number;
  explanation: string;
}

export interface MyhillNerodeCell {
  stateA: number;
  stateB: number;
  distinguishable: boolean;
  witnessSuffix: string | null; // null if equivalent, '' if 0-step (accept vs non-accept)
  roundIdentified: number;
}

export interface RedosAnalysis {
  riskLevel: 'IMMUNE (O(|w|) DFA)' | 'POLYNOMIAL NFA AMBIGUITY' | 'EXPONENTIAL BACKTRACKING TRAP';
  backtrackerRisk: 'LOW' | 'MEDIUM' | 'CRITICAL';
  starHeight: number;
  nondeterministicBranching: number;
  explanation: string;
  evilPayloadSample: string | null;
}

export interface RegexCompilationResult {
  regex: string;
  normalizedRegex: string;
  isAnchoredStart: boolean;
  isAnchoredEnd: boolean;
  rawTokens: Token[];
  concatTokens: Token[];
  postfixTokens: Token[];
  postfixString: string;
  ast: ASTNode;
  minterms: MintermClass[];
  nfa: CompiledNFA;
  powersetDfa: CompiledDFA;
  minimalDfa: CompiledDFA;
  hopcroftSteps: HopcroftSplitStep[];
  myhillNerodeTable: MyhillNerodeCell[];
  redosAnalysis: RedosAnalysis;
  compileTimeMs: number;
}

export interface DualTraceStep {
  stepIndex: number;
  char: string;
  nfaBefore: number[];
  nfaDirectMove: number[];
  nfaEpsilonAdditions: number[];
  nfaAfter: number[];
  powersetBefore: number | null;
  powersetAfter: number | null;
  minimalBefore: number | null;
  minimalAfter: number | null;
  nfaAcceptsHere: boolean;
  dfaAcceptsHere: boolean;
  matchedMintermLabel: string;
}

export interface DualSimulationResult {
  input: string;
  isAccepted: boolean;
  nfaInitialStates: number[];
  nfaFinalStates: number[];
  powersetInitialState: number;
  powersetFinalState: number | null;
  minimalInitialState: number;
  minimalFinalState: number | null;
  steps: DualTraceStep[];
  elapsedMs: number;
}

export interface EquivalenceProofResult {
  regex1: string;
  regex2: string;
  isEquivalent: boolean;
  isSubset1Of2: boolean;
  isSubset2Of1: boolean;
  isDisjoint: boolean;
  relationSummary:
    | 'EQUIVALENT (L₁ ≡ L₂)'
    | 'STRICT SUBSET (L₁ ⊂ L₂)'
    | 'STRICT SUPERSET (L₁ ⊃ L₂)'
    | 'DISJOINT (L₁ ∩ L₂ = ∅)'
    | 'OVERLAPPING (L₁ ≉ L₂)';
  witness1Minus2: string | null;
  witness2Minus1: string | null;
  witnessIntersection: string | null;
  compiled1: RegexCompilationResult;
  compiled2: RegexCompilationResult;
  formalProofSteps: string[];
}

const PRECEDENCE: Record<string, number> = {
  [TokenType.STAR]: 5,
  [TokenType.PLUS]: 5,
  [TokenType.OPTIONAL]: 5,
  [TokenType.QUANTIFIER]: 5,
  [TokenType.COMPLEMENT]: 4,
  [TokenType.CONCAT]: 3,
  [TokenType.INTERSECT]: 2,
  [TokenType.UNION]: 1,
};

function formatCharDisplay(c: string): string {
  if (c === ' ') return '␣';
  if (c === '\t') return '\\t';
  return c;
}

function parseCharacterClass(regexStr: string, startIdx: number): [Token, number] {
  const n = regexStr.length;
  let i = startIdx + 1;
  let isNegated = false;

  if (i < n && regexStr[i] === '^') {
    isNegated = true;
    i++;
  }
  if (i >= n) {
    throw new Error(`Syntax Error: Unclosed character class '[' at position ${startIdx}`);
  }
  if (regexStr[i] === ']') {
    throw new Error(`Syntax Error: Empty character class '[]' at position ${startIdx}`);
  }

  const chars = new Set<string>();
  while (i < n) {
    if (regexStr[i] === ']') {
      const finalSet = isNegated
        ? new Set(PRINTABLE_ASCII.filter((c) => !chars.has(c)))
        : new Set(chars);
      const rawVal = regexStr.slice(startIdx, i + 1);
      return [
        {
          type: TokenType.CHAR_CLASS,
          value: rawVal,
          pos: startIdx,
          charset: finalSet,
        },
        i + 1,
      ];
    }

    let currChar = '';
    if (regexStr[i] === '\\') {
      if (i + 1 >= n) {
        throw new Error(`Syntax Error: Trailing backslash in character class at position ${i}`);
      }
      const esc = regexStr[i + 1];
      if (SHORTHANDS[esc]) {
        SHORTHANDS[esc].chars.forEach((c) => chars.add(c));
        i += 2;
        continue;
      } else {
        currChar = esc;
        i += 2;
      }
    } else {
      currChar = regexStr[i];
      i++;
    }

    if (i < n && regexStr[i] === '-' && i + 1 < n && regexStr[i + 1] !== ']') {
      i++; // consume '-'
      let endChar = '';
      if (regexStr[i] === '\\') {
        if (i + 1 >= n) {
          throw new Error(`Syntax Error: Trailing backslash in range at position ${i}`);
        }
        const esc2 = regexStr[i + 1];
        if (SHORTHANDS[esc2]) {
          throw new Error(`Syntax Error: Shorthand '\\${esc2}' cannot be range bound at position ${i}`);
        }
        endChar = esc2;
        i += 2;
      } else {
        endChar = regexStr[i];
        i++;
      }

      if (currChar.charCodeAt(0) > endChar.charCodeAt(0)) {
        throw new Error(
          `Syntax Error: Invalid range '${currChar}-${endChar}' at position ${i - 3}: bounds out of order`
        );
      }
      for (let code = currChar.charCodeAt(0); code <= endChar.charCodeAt(0); code++) {
        chars.add(String.fromCharCode(code));
      }
    } else {
      chars.add(currChar);
    }
  }

  throw new Error(`Syntax Error: Unclosed character class '[' at position ${startIdx}`);
}

function parseBoundedQuantifier(regexStr: string, startIdx: number): [Token, number] {
  const closeIdx = regexStr.indexOf('}', startIdx + 1);
  if (closeIdx === -1) {
    throw new Error(`Syntax Error: Unclosed quantifier '{' at position ${startIdx}`);
  }
  const body = regexStr.slice(startIdx + 1, closeIdx).trim();
  if (!body) {
    throw new Error(`Syntax Error: Empty quantifier '{}' at position ${startIdx}`);
  }

  const parts = body.split(',');
  if (parts.length > 2) {
    throw new Error(`Syntax Error: Malformed quantifier '{${body}}' at position ${startIdx}`);
  }

  const minVal = parseInt(parts[0].trim(), 10);
  if (isNaN(minVal) || minVal < 0 || minVal > 32) {
    throw new Error(
      `Syntax Error: Quantifier lower bound in '{${body}}' at position ${startIdx} must be an integer in 0..32`
    );
  }

  let maxVal: number | null = minVal;
  if (parts.length === 2) {
    const rightTrim = parts[1].trim();
    if (rightTrim === '') {
      maxVal = null; // {n,}
    } else {
      maxVal = parseInt(rightTrim, 10);
      if (isNaN(maxVal) || maxVal < minVal || maxVal > 32) {
        throw new Error(
          `Syntax Error: Quantifier upper bound in '{${body}}' at position ${startIdx} must satisfy ${minVal} <= m <= 32`
        );
      }
    }
  }

  return [
    {
      type: TokenType.QUANTIFIER,
      value: `{${body}}`,
      pos: startIdx,
      minRepeat: minVal,
      maxRepeat: maxVal,
    },
    closeIdx + 1,
  ];
}

export function tokenizeRegex(rawRegex: string): {
  tokens: Token[];
  isAnchoredStart: boolean;
  isAnchoredEnd: boolean;
  normalizedRegex: string;
} {
  if (!rawRegex) {
    throw new Error('Syntax Error: Regular expression cannot be empty');
  }

  let working = rawRegex;
  let isAnchoredStart = false;
  let isAnchoredEnd = false;

  if (working.startsWith('^')) {
    isAnchoredStart = true;
    working = working.slice(1);
  }
  if (working.endsWith('$') && !working.endsWith('\\$')) {
    isAnchoredEnd = true;
    working = working.slice(0, -1);
  }

  if (!working) {
    throw new Error('Syntax Error: Expression contains only anchors with no pattern body');
  }

  const tokens: Token[] = [];
  let i = 0;
  const n = working.length;
  let parenDepth = 0;

  while (i < n) {
    const char = working[i];

    if (char === '\\') {
      if (i + 1 >= n) {
        throw new Error(`Syntax Error: Trailing backslash at position ${i}`);
      }
      const esc = working[i + 1];
      if (SHORTHANDS[esc]) {
        tokens.push({
          type: TokenType.CHAR_CLASS,
          value: SHORTHANDS[esc].display,
          pos: i,
          charset: new Set(SHORTHANDS[esc].chars),
        });
        i += 2;
      } else if (esc === 'x' && i + 3 < n) {
        const hex = working.slice(i + 2, i + 4);
        const code = parseInt(hex, 16);
        if (!isNaN(code)) {
          tokens.push({
            type: TokenType.CHAR,
            value: String.fromCharCode(code),
            pos: i,
            escaped: true,
          });
          i += 4;
        } else {
          tokens.push({ type: TokenType.CHAR, value: esc, pos: i, escaped: true });
          i += 2;
        }
      } else {
        tokens.push({ type: TokenType.CHAR, value: esc, pos: i, escaped: true });
        i += 2;
      }
    } else if (char === '[') {
      const [tok, nextI] = parseCharacterClass(working, i);
      tokens.push(tok);
      i = nextI;
    } else if (char === '{') {
      const [tok, nextI] = parseBoundedQuantifier(working, i);
      tokens.push(tok);
      i = nextI;
    } else if (char === '(') {
      // Support non-capturing group syntax (?:...) transparently
      if (working.slice(i, i + 3) === '(?:') {
        tokens.push({ type: TokenType.LPAREN, value: '(', pos: i });
        parenDepth++;
        i += 3;
      } else {
        tokens.push({ type: TokenType.LPAREN, value: '(', pos: i });
        parenDepth++;
        i++;
      }
    } else if (char === ')') {
      if (parenDepth <= 0) {
        throw new Error(`Syntax Error: Unmatched closing parenthesis ')' at position ${i}`);
      }
      tokens.push({ type: TokenType.RPAREN, value: ')', pos: i });
      parenDepth--;
      i++;
    } else if (char === '*') {
      tokens.push({ type: TokenType.STAR, value: '*', pos: i });
      i++;
    } else if (char === '+') {
      tokens.push({ type: TokenType.PLUS, value: '+', pos: i });
      i++;
    } else if (char === '?') {
      tokens.push({ type: TokenType.OPTIONAL, value: '?', pos: i });
      i++;
    } else if (char === '~') {
      tokens.push({ type: TokenType.COMPLEMENT, value: '~', pos: i });
      i++;
    } else if (char === '&') {
      tokens.push({ type: TokenType.INTERSECT, value: '&', pos: i });
      i++;
    } else if (char === '|') {
      tokens.push({ type: TokenType.UNION, value: '|', pos: i });
      i++;
    } else if (char === '.') {
      tokens.push({ type: TokenType.ANY, value: '.', pos: i });
      i++;
    } else if (char === '^' || char === '$') {
      throw new Error(
        `Syntax Error: Anchor '${char}' at position ${i} must appear at pattern boundary`
      );
    } else {
      tokens.push({ type: TokenType.CHAR, value: char, pos: i });
      i++;
    }
  }

  if (parenDepth > 0) {
    throw new Error(`Syntax Error: Unmatched opening parenthesis '(' (depth=${parenDepth})`);
  }

  const postfixQuantifiers = new Set([
    TokenType.STAR,
    TokenType.PLUS,
    TokenType.OPTIONAL,
    TokenType.QUANTIFIER,
  ]);
  const binaryOps = new Set([TokenType.UNION, TokenType.INTERSECT]);

  for (let idx = 0; idx < tokens.length - 1; idx++) {
    const t1 = tokens[idx];
    const t2 = tokens[idx + 1];
    if (postfixQuantifiers.has(t1.type) && postfixQuantifiers.has(t2.type)) {
      throw new Error(
        `Syntax Error: Consecutive quantifiers '${t1.value}${t2.value}' at position ${t2.pos}`
      );
    }
    if (binaryOps.has(t1.type) && binaryOps.has(t2.type)) {
      throw new Error(
        `Syntax Error: Consecutive binary operators '${t1.value}${t2.value}' at position ${t2.pos}`
      );
    }
    if (t1.type === TokenType.LPAREN && t2.type === TokenType.RPAREN) {
      throw new Error(`Syntax Error: Empty group '()' at position ${t1.pos}`);
    }
  }

  if (
    tokens.length > 0 &&
    (postfixQuantifiers.has(tokens[0].type) || binaryOps.has(tokens[0].type))
  ) {
    throw new Error(`Syntax Error: Expression cannot start with operator '${tokens[0].value}'`);
  }

  if (
    tokens.length > 0 &&
    (binaryOps.has(tokens[tokens.length - 1].type) ||
      tokens[tokens.length - 1].type === TokenType.COMPLEMENT)
  ) {
    throw new Error(
      `Syntax Error: Expression cannot end with trailing operator '${tokens[tokens.length - 1].value}'`
    );
  }

  return {
    tokens,
    isAnchoredStart,
    isAnchoredEnd,
    normalizedRegex: working,
  };
}

export function insertExplicitConcat(tokens: Token[]): Token[] {
  if (tokens.length === 0) return [];
  const result: Token[] = [];

  const canEnd = new Set([
    TokenType.CHAR,
    TokenType.ANY,
    TokenType.CHAR_CLASS,
    TokenType.STAR,
    TokenType.PLUS,
    TokenType.OPTIONAL,
    TokenType.QUANTIFIER,
    TokenType.RPAREN,
  ]);

  const canStart = new Set([
    TokenType.CHAR,
    TokenType.ANY,
    TokenType.CHAR_CLASS,
    TokenType.COMPLEMENT,
    TokenType.LPAREN,
  ]);

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (i > 0) {
      const prev = tokens[i - 1];
      if (canEnd.has(prev.type) && canStart.has(token.type)) {
        result.push({ type: TokenType.CONCAT, value: '·', pos: token.pos });
      }
    }
    result.push(token);
  }
  return result;
}

export function infixToPostfix(tokens: Token[]): Token[] {
  const output: Token[] = [];
  const stack: Token[] = [];

  for (const token of tokens) {
    if (
      token.type === TokenType.CHAR ||
      token.type === TokenType.ANY ||
      token.type === TokenType.CHAR_CLASS
    ) {
      output.push(token);
    } else if (token.type === TokenType.LPAREN) {
      stack.push(token);
    } else if (token.type === TokenType.RPAREN) {
      while (stack.length > 0 && stack[stack.length - 1].type !== TokenType.LPAREN) {
        output.push(stack.pop()!);
      }
      if (stack.length === 0) {
        throw new Error("Mismatched parentheses: Missing '('");
      }
      stack.pop();
    } else if (PRECEDENCE[token.type] !== undefined) {
      const currPrec = PRECEDENCE[token.type];
      // COMPLEMENT (~) is right-associative unary prefix operator
      const isRightAssoc = token.type === TokenType.COMPLEMENT;
      while (
        stack.length > 0 &&
        PRECEDENCE[stack[stack.length - 1].type] !== undefined &&
        (isRightAssoc
          ? PRECEDENCE[stack[stack.length - 1].type] > currPrec
          : PRECEDENCE[stack[stack.length - 1].type] >= currPrec)
      ) {
        output.push(stack.pop()!);
      }
      stack.push(token);
    } else {
      throw new Error(`Unexpected token: ${token.value}`);
    }
  }

  while (stack.length > 0) {
    const top = stack.pop()!;
    if (top.type === TokenType.LPAREN || top.type === TokenType.RPAREN) {
      throw new Error('Mismatched parentheses');
    }
    output.push(top);
  }

  return output;
}

export function buildAST(postfixTokens: Token[]): ASTNode {
  let nodeCounter = 0;
  const nextId = () => `ast_${nodeCounter++}`;
  const stack: ASTNode[] = [];

  for (const token of postfixTokens) {
    if (token.type === TokenType.CHAR) {
      stack.push({
        id: nextId(),
        kind: 'Literal',
        label: `'${formatCharDisplay(token.value)}'`,
        char: token.value,
        children: [],
      });
    } else if (token.type === TokenType.ANY) {
      stack.push({
        id: nextId(),
        kind: 'Wildcard',
        label: 'Σ (.)',
        children: [],
      });
    } else if (token.type === TokenType.CHAR_CLASS) {
      stack.push({
        id: nextId(),
        kind: 'CharClass',
        label: token.value,
        charset: token.charset ? new Set(token.charset) : new Set(),
        children: [],
      });
    } else if (token.type === TokenType.STAR) {
      if (stack.length < 1) throw new Error('AST Error: Missing operand for *');
      const child = stack.pop()!;
      stack.push({
        id: nextId(),
        kind: 'Star',
        label: '* (Kleene)',
        children: [child],
      });
    } else if (token.type === TokenType.PLUS) {
      if (stack.length < 1) throw new Error('AST Error: Missing operand for +');
      const child = stack.pop()!;
      stack.push({
        id: nextId(),
        kind: 'Plus',
        label: '+ (Positive)',
        children: [child],
      });
    } else if (token.type === TokenType.OPTIONAL) {
      if (stack.length < 1) throw new Error('AST Error: Missing operand for ?');
      const child = stack.pop()!;
      stack.push({
        id: nextId(),
        kind: 'Optional',
        label: '? (Optional)',
        children: [child],
      });
    } else if (token.type === TokenType.QUANTIFIER) {
      if (stack.length < 1) throw new Error(`AST Error: Missing operand for ${token.value}`);
      const child = stack.pop()!;
      stack.push({
        id: nextId(),
        kind: 'Repeat',
        label: token.value,
        minRepeat: token.minRepeat,
        maxRepeat: token.maxRepeat,
        children: [child],
      });
    } else if (token.type === TokenType.COMPLEMENT) {
      if (stack.length < 1) throw new Error('AST Error: Missing operand for ~ (Complement)');
      const child = stack.pop()!;
      stack.push({
        id: nextId(),
        kind: 'Complement',
        label: '~ (Complement)',
        children: [child],
      });
    } else if (token.type === TokenType.CONCAT) {
      if (stack.length < 2) throw new Error('AST Error: Insufficient operands for Concatenation');
      const right = stack.pop()!;
      const left = stack.pop()!;
      stack.push({
        id: nextId(),
        kind: 'Concat',
        label: '· (Concat)',
        children: [left, right],
      });
    } else if (token.type === TokenType.INTERSECT) {
      if (stack.length < 2) throw new Error('AST Error: Insufficient operands for Intersection (&)');
      const right = stack.pop()!;
      const left = stack.pop()!;
      stack.push({
        id: nextId(),
        kind: 'Intersect',
        label: '& (Intersect)',
        children: [left, right],
      });
    } else if (token.type === TokenType.UNION) {
      if (stack.length < 2) throw new Error('AST Error: Insufficient operands for Union (|)');
      const right = stack.pop()!;
      const left = stack.pop()!;
      stack.push({
        id: nextId(),
        kind: 'Union',
        label: '| (Union)',
        children: [left, right],
      });
    }
  }

  if (stack.length !== 1) {
    throw new Error(`AST Error: Malformed expression (${stack.length} roots remaining)`);
  }
  return stack[0];
}

/**
 * Computes Disjoint Alphabet Minterms (Σ / ~) from the AST.
 * Two characters c1, c2 belong to the same equivalence class iff every
 * literal and character class in the AST treats c1 and c2 identically.
 */
export function computeMintermsFromAST(ast: ASTNode, extraSets: Set<string>[] = []): MintermClass[] {
  const charSets: Set<string>[] = [...extraSets];
  let usesWildcardOrComplement = false;

  function walk(node: ASTNode) {
    if (node.kind === 'Literal' && node.char) {
      charSets.push(new Set([node.char]));
    } else if (node.kind === 'CharClass' && node.charset) {
      charSets.push(new Set(node.charset));
    } else if (node.kind === 'Wildcard' || node.kind === 'Complement') {
      usesWildcardOrComplement = true;
    }
    node.children.forEach(walk);
  }
  walk(ast);

  // Partition PRINTABLE_ASCII by signature bitmask across charSets
  const sigMap = new Map<string, string[]>();
  for (const ch of PRINTABLE_ASCII) {
    const bits = charSets.map((s) => (s.has(ch) ? '1' : '0')).join('');
    if (!sigMap.has(bits)) {
      sigMap.set(bits, []);
    }
    sigMap.get(bits)!.push(ch);
  }

  const allZeroSig = '0'.repeat(charSets.length);
  const classes: MintermClass[] = [];

  for (const [sig, chars] of sigMap.entries()) {
    if (sig === allZeroSig && !usesWildcardOrComplement && charSets.length > 0) {
      // Characters not matched by any literal/charset and no wildcard/complement present
      continue;
    }
    const isCatchAll = sig === allZeroSig;
    const charSet = new Set(chars);
    const label = formatMintermLabel(chars, isCatchAll);
    classes.push({
      id: 0,
      label,
      sampleChar: chars[0],
      chars: charSet,
      isCatchAll,
    });
  }

  // Sort classes: non-catchall first ordered by sampleChar, catchall last
  classes.sort((a, b) => {
    if (a.isCatchAll !== b.isCatchAll) return a.isCatchAll ? 1 : -1;
    return a.sampleChar.localeCompare(b.sampleChar);
  });

  if (classes.length === 0) {
    classes.push({
      id: 0,
      label: 'a',
      sampleChar: 'a',
      chars: new Set(['a']),
      isCatchAll: false,
    });
  }

  classes.forEach((c, idx) => {
    c.id = idx;
  });

  return classes;
}

function formatMintermLabel(chars: string[], isCatchAll: boolean): string {
  if (isCatchAll) {
    return chars.length === PRINTABLE_ASCII.length ? 'Σ' : 'Σ\\{…}';
  }
  if (chars.length === 1) {
    return formatCharDisplay(chars[0]);
  }
  if (chars.length <= 3) {
    return `{${chars.map(formatCharDisplay).join(',')}}`;
  }
  // Detect contiguous ASCII intervals
  const codes = chars.map((c) => c.charCodeAt(0)).sort((a, b) => a - b);
  const ranges: string[] = [];
  let start = codes[0];
  let prev = codes[0];

  for (let i = 1; i <= codes.length; i++) {
    const curr = codes[i];
    if (curr === prev + 1) {
      prev = curr;
    } else {
      if (start === prev) {
        ranges.push(formatCharDisplay(String.fromCharCode(start)));
      } else if (prev === start + 1) {
        ranges.push(
          `${formatCharDisplay(String.fromCharCode(start))}${formatCharDisplay(String.fromCharCode(prev))}`
        );
      } else {
        ranges.push(
          `${formatCharDisplay(String.fromCharCode(start))}-${formatCharDisplay(String.fromCharCode(prev))}`
        );
      }
      start = curr;
      prev = curr;
    }
  }
  const joined = ranges.join('');
  return `[${joined.length > 10 ? joined.slice(0, 9) + '…' : joined}]`;
}

// ============================================================================
// Internal Mutable Thompson Fragment Builder
// ============================================================================

class MutableState {
  id: number;
  isAccept = false;
  transitions: {
    symbolKind: 'EPSILON' | 'CHAR' | 'ANY' | 'CHARSET';
    display: string;
    char?: string;
    charset?: Set<string>;
    target: MutableState;
  }[] = [];

  constructor(id: number) {
    this.id = id;
  }

  addTransition(
    symbolKind: 'EPSILON' | 'CHAR' | 'ANY' | 'CHARSET',
    display: string,
    target: MutableState,
    char?: string,
    charset?: Set<string>
  ) {
    const exists = this.transitions.some(
      (t) => t.symbolKind === symbolKind && t.display === display && t.target === target
    );
    if (!exists) {
      this.transitions.push({ symbolKind, display, char, charset, target });
    }
  }
}

interface MutableFragment {
  start: MutableState;
  accept: MutableState;
}

export function buildThompsonNFAFromAST(ast: ASTNode, minterms: MintermClass[]): CompiledNFA {
  let stateCounter = 0;
  const newState = () => new MutableState(stateCounter++);

  function buildNode(node: ASTNode): MutableFragment {
    if (node.kind === 'Literal') {
      const s0 = newState();
      const s1 = newState();
      s0.addTransition('CHAR', formatCharDisplay(node.char!), s1, node.char!);
      return { start: s0, accept: s1 };
    }

    if (node.kind === 'Wildcard') {
      const s0 = newState();
      const s1 = newState();
      s0.addTransition('ANY', WILDCARD, s1);
      return { start: s0, accept: s1 };
    }

    if (node.kind === 'CharClass') {
      const s0 = newState();
      const s1 = newState();
      s0.addTransition('CHARSET', node.label, s1, undefined, node.charset);
      return { start: s0, accept: s1 };
    }

    if (node.kind === 'Concat') {
      const f1 = buildNode(node.children[0]);
      const f2 = buildNode(node.children[1]);
      f1.accept.addTransition('EPSILON', EPSILON, f2.start);
      return { start: f1.start, accept: f2.accept };
    }

    if (node.kind === 'Union') {
      const f1 = buildNode(node.children[0]);
      const f2 = buildNode(node.children[1]);
      const start = newState();
      const accept = newState();
      start.addTransition('EPSILON', EPSILON, f1.start);
      start.addTransition('EPSILON', EPSILON, f2.start);
      f1.accept.addTransition('EPSILON', EPSILON, accept);
      f2.accept.addTransition('EPSILON', EPSILON, accept);
      return { start, accept };
    }

    if (node.kind === 'Star') {
      const inner = buildNode(node.children[0]);
      const start = newState();
      const accept = newState();
      start.addTransition('EPSILON', EPSILON, accept);
      start.addTransition('EPSILON', EPSILON, inner.start);
      inner.accept.addTransition('EPSILON', EPSILON, inner.start);
      inner.accept.addTransition('EPSILON', EPSILON, accept);
      return { start, accept };
    }

    if (node.kind === 'Plus') {
      const inner = buildNode(node.children[0]);
      const start = newState();
      const accept = newState();
      start.addTransition('EPSILON', EPSILON, inner.start);
      inner.accept.addTransition('EPSILON', EPSILON, inner.start);
      inner.accept.addTransition('EPSILON', EPSILON, accept);
      return { start, accept };
    }

    if (node.kind === 'Optional') {
      const inner = buildNode(node.children[0]);
      const start = newState();
      const accept = newState();
      start.addTransition('EPSILON', EPSILON, accept);
      start.addTransition('EPSILON', EPSILON, inner.start);
      inner.accept.addTransition('EPSILON', EPSILON, accept);
      return { start, accept };
    }

    if (node.kind === 'Repeat') {
      const minR = node.minRepeat ?? 0;
      const maxR = node.maxRepeat;
      const childAst = node.children[0];

      // Build minR mandatory copies concatenated
      let prefixFrag: MutableFragment | null = null;
      for (let i = 0; i < minR; i++) {
        const copy = buildNode(childAst);
        if (!prefixFrag) {
          prefixFrag = copy;
        } else {
          prefixFrag.accept.addTransition('EPSILON', EPSILON, copy.start);
          prefixFrag = { start: prefixFrag.start, accept: copy.accept };
        }
      }

      if (maxR === null) {
        // {n,}: prefix followed by Kleene star of childAst
        const tailStar = buildNode({
          id: `${node.id}_star`,
          kind: 'Star',
          label: '*',
          children: [childAst],
        });
        if (!prefixFrag) return tailStar;
        prefixFrag.accept.addTransition('EPSILON', EPSILON, tailStar.start);
        return { start: prefixFrag.start, accept: tailStar.accept };
      }

      const optCount = (maxR ?? minR) - minR;
      for (let i = 0; i < optCount; i++) {
        const optCopy = buildNode({
          id: `${node.id}_opt_${i}`,
          kind: 'Optional',
          label: '?',
          children: [childAst],
        });
        if (!prefixFrag) {
          prefixFrag = optCopy;
        } else {
          prefixFrag.accept.addTransition('EPSILON', EPSILON, optCopy.start);
          prefixFrag = { start: prefixFrag.start, accept: optCopy.accept };
        }
      }

      if (!prefixFrag) {
        // {0,0}: matches empty string ε
        const s0 = newState();
        const s1 = newState();
        s0.addTransition('EPSILON', EPSILON, s1);
        return { start: s0, accept: s1 };
      }
      return prefixFrag;
    }

    if (node.kind === 'Complement') {
      // Compile child to complete DFA over PRINTABLE_ASCII, invert accept states, convert back to Thompson fragment
      const childNfa = finalizeNFA(buildNode(node.children[0]));
      const childDfa = determinizeNFA(childNfa, minterms);
      return dfaComplementToMutableFragment(childDfa, minterms, newState);
    }

    if (node.kind === 'Intersect') {
      // Compile left and right to DFAs, construct product intersection DFA, convert back to Thompson fragment
      const leftNfa = finalizeNFA(buildNode(node.children[0]));
      const rightNfa = finalizeNFA(buildNode(node.children[1]));
      const leftDfa = determinizeNFA(leftNfa, minterms);
      const rightDfa = determinizeNFA(rightNfa, minterms);
      return dfaIntersectionToMutableFragment(leftDfa, rightDfa, minterms, newState);
    }

    throw new Error(`Unsupported AST node kind: ${node.kind}`);
  }

  const rootFrag = buildNode(ast);
  return finalizeNFA(rootFrag);
}

function dfaComplementToMutableFragment(
  dfa: CompiledDFA,
  minterms: MintermClass[],
  newState: () => MutableState
): MutableFragment {
  const start = newState();
  const accept = newState();
  const stateMap = new Map<number, MutableState>();

  for (const sid of dfa.states.keys()) {
    stateMap.set(sid, newState());
  }
  const deadSink = newState();
  // Dead sink in original DFA is non-accepting -> in complement it IS accepting!
  deadSink.addTransition('EPSILON', EPSILON, accept);
  deadSink.addTransition('ANY', WILDCARD, deadSink);

  start.addTransition('EPSILON', EPSILON, stateMap.get(dfa.startStateId)!);

  for (const [sid, dState] of dfa.states.entries()) {
    const mState = stateMap.get(sid)!;
    if (!dState.isAccept) {
      mState.addTransition('EPSILON', EPSILON, accept);
    }
    const coveredChars = new Set<string>();
    for (const mt of minterms) {
      const targetId = dState.transitions.get(mt.label);
      if (targetId !== undefined) {
        mt.chars.forEach((c) => coveredChars.add(c));
        mState.addTransition('CHARSET', mt.label, stateMap.get(targetId)!, undefined, mt.chars);
      }
    }
    const missingChars = new Set(PRINTABLE_ASCII.filter((c) => !coveredChars.has(c)));
    if (missingChars.size > 0) {
      mState.addTransition(
        'CHARSET',
        formatMintermLabel(Array.from(missingChars), false),
        deadSink,
        undefined,
        missingChars
      );
    }
  }

  return { start, accept };
}

function dfaIntersectionToMutableFragment(
  dfa1: CompiledDFA,
  dfa2: CompiledDFA,
  minterms: MintermClass[],
  newState: () => MutableState
): MutableFragment {
  const start = newState();
  const accept = newState();
  const pairMap = new Map<string, MutableState>();
  const queue: [number, number][] = [[dfa1.startStateId, dfa2.startStateId]];
  const startKey = `${dfa1.startStateId}_${dfa2.startStateId}`;
  pairMap.set(startKey, newState());
  start.addTransition('EPSILON', EPSILON, pairMap.get(startKey)!);

  while (queue.length > 0) {
    const [s1, s2] = queue.shift()!;
    const currMutable = pairMap.get(`${s1}_${s2}`)!;
    const st1 = dfa1.states.get(s1)!;
    const st2 = dfa2.states.get(s2)!;

    if (st1.isAccept && st2.isAccept) {
      currMutable.addTransition('EPSILON', EPSILON, accept);
    }

    for (const mt of minterms) {
      const t1 = st1.charTransitions.get(mt.sampleChar);
      const t2 = st2.charTransitions.get(mt.sampleChar);
      if (t1 !== undefined && t2 !== undefined) {
        const nextKey = `${t1}_${t2}`;
        if (!pairMap.has(nextKey)) {
          pairMap.set(nextKey, newState());
          queue.push([t1, t2]);
        }
        currMutable.addTransition(
          'CHARSET',
          mt.label,
          pairMap.get(nextKey)!,
          undefined,
          mt.chars
        );
      }
    }
  }

  return { start, accept };
}

function finalizeNFA(frag: MutableFragment): CompiledNFA {
  frag.accept.isAccept = true;

  // BFS topological ordering from frag.start
  const visited = new Set<MutableState>([frag.start]);
  const ordered: MutableState[] = [];
  const queue: MutableState[] = [frag.start];

  while (queue.length > 0) {
    const curr = queue.shift()!;
    ordered.push(curr);
    for (const tr of curr.transitions) {
      if (!visited.has(tr.target)) {
        visited.add(tr.target);
        queue.push(tr.target);
      }
    }
  }

  // Ensure accept state is numbered last for clean textbook presentation
  const withoutAccept = ordered.filter((s) => s !== frag.accept);
  if (visited.has(frag.accept)) {
    withoutAccept.push(frag.accept);
  }
  withoutAccept.forEach((s, idx) => {
    s.id = idx;
  });

  const states = new Map<number, NFAStateData>();
  const alphabetSet = new Set<string>();
  let hasWildcard = false;

  for (const s of withoutAccept) {
    const transitions: NFATransition[] = s.transitions.map((t) => {
      if (t.symbolKind === 'CHAR' && t.char) {
        alphabetSet.add(t.char);
      }
      if (t.symbolKind === 'ANY') {
        hasWildcard = true;
      }
      return {
        symbolKind: t.symbolKind,
        display: t.display,
        char: t.char,
        charset: t.charset,
        targetId: t.target.id,
      };
    });

    states.set(s.id, {
      id: s.id,
      isStart: s === frag.start,
      isAccept: s === frag.accept || s.isAccept,
      transitions,
    });
  }

  return {
    startStateId: frag.start.id,
    acceptStateId: frag.accept.id,
    states,
    alphabet: Array.from(alphabetSet).sort(),
    hasWildcard,
  };
}

// ============================================================================
// NFA Simulation Primitives (ε-Closure & MOVE)
// ============================================================================

export function computeEpsilonClosure(nfa: CompiledNFA, stateIds: Iterable<number>): Set<number> {
  const closure = new Set<number>(stateIds);
  const stack = Array.from(stateIds);

  while (stack.length > 0) {
    const currId = stack.pop()!;
    const state = nfa.states.get(currId);
    if (!state) continue;
    for (const tr of state.transitions) {
      if (tr.symbolKind === 'EPSILON' && !closure.has(tr.targetId)) {
        closure.add(tr.targetId);
        stack.push(tr.targetId);
      }
    }
  }
  return closure;
}

export function transitionMatchesChar(tr: NFATransition, ch: string): boolean {
  if (tr.symbolKind === 'EPSILON') return false;
  if (tr.symbolKind === 'ANY') return true;
  if (tr.symbolKind === 'CHAR') return tr.char === ch;
  if (tr.symbolKind === 'CHARSET') return tr.charset ? tr.charset.has(ch) : false;
  return false;
}

export function computeMove(nfa: CompiledNFA, stateIds: Iterable<number>, ch: string): Set<number> {
  const direct = new Set<number>();
  for (const sid of stateIds) {
    const st = nfa.states.get(sid);
    if (!st) continue;
    for (const tr of st.transitions) {
      if (transitionMatchesChar(tr, ch)) {
        direct.add(tr.targetId);
      }
    }
  }
  return direct;
}

// ============================================================================
// Rabin-Scott Powerset Construction over Disjoint Minterm Classes
// ============================================================================

export function determinizeNFA(nfa: CompiledNFA, minterms: MintermClass[]): CompiledDFA {
  const startClosure = Array.from(computeEpsilonClosure(nfa, [nfa.startStateId])).sort(
    (a, b) => a - b
  );
  const startKey = startClosure.join(',');

  const subsetToId = new Map<string, number>();
  const states = new Map<number, DFAStateData>();
  const queue: number[][] = [startClosure];

  subsetToId.set(startKey, 0);
  states.set(0, {
    id: 0,
    name: 'D0',
    isStart: true,
    isAccept: startClosure.some((id) => nfa.states.get(id)?.isAccept),
    nfaStateIds: startClosure,
    powersetStateIds: [0],
    transitions: new Map(),
    charTransitions: new Map(),
  });

  while (queue.length > 0) {
    const currSubset = queue.shift()!;
    const currKey = currSubset.join(',');
    const currDfaId = subsetToId.get(currKey)!;
    const currDfaState = states.get(currDfaId)!;

    for (const mt of minterms) {
      const direct = computeMove(nfa, currSubset, mt.sampleChar);
      if (direct.size === 0) continue;

      const nextClosure = Array.from(computeEpsilonClosure(nfa, direct)).sort((a, b) => a - b);
      const nextKey = nextClosure.join(',');

      let targetDfaId = subsetToId.get(nextKey);
      if (targetDfaId === undefined) {
        targetDfaId = states.size;
        subsetToId.set(nextKey, targetDfaId);
        states.set(targetDfaId, {
          id: targetDfaId,
          name: `D${targetDfaId}`,
          isStart: false,
          isAccept: nextClosure.some((id) => nfa.states.get(id)?.isAccept),
          nfaStateIds: nextClosure,
          powersetStateIds: [targetDfaId],
          transitions: new Map(),
          charTransitions: new Map(),
        });
        queue.push(nextClosure);
      }

      currDfaState.transitions.set(mt.label, targetDfaId);
      for (const ch of mt.chars) {
        currDfaState.charTransitions.set(ch, targetDfaId);
      }
    }
  }

  return {
    kind: 'POWERSET',
    startStateId: 0,
    states,
    minterms,
    alphabetLabels: minterms.map((m) => m.label),
  };
}

// ============================================================================
// Hopcroft's O(|Σ| · |Q| log |Q|) Partition Refinement + Step Trace + Myhill-Nerode
// ============================================================================

export function minimizeDFAWithTrace(powersetDfa: CompiledDFA): {
  minimalDfa: CompiledDFA;
  hopcroftSteps: HopcroftSplitStep[];
  myhillNerodeTable: MyhillNerodeCell[];
} {
  const TRAP_ID = -1;
  const alphabet = powersetDfa.alphabetLabels;
  const reachableIds = Array.from(powersetDfa.states.keys()).sort((a, b) => a - b);

  // Check if partial transitions exist -> add explicit TRAP_ID for sound total transition refinement
  let needsTrap = false;
  for (const sid of reachableIds) {
    const st = powersetDfa.states.get(sid)!;
    for (const sym of alphabet) {
      if (!st.transitions.has(sym)) {
        needsTrap = true;
        break;
      }
    }
    if (needsTrap) break;
  }

  const acceptIds: number[] = [];
  const nonAcceptIds: number[] = [];
  for (const sid of reachableIds) {
    if (powersetDfa.states.get(sid)!.isAccept) {
      acceptIds.push(sid);
    } else {
      nonAcceptIds.push(sid);
    }
  }
  if (needsTrap) {
    nonAcceptIds.push(TRAP_ID);
  }

  // Build inverse transition map inv[sym][target] -> Set<source>
  const invTrans = new Map<string, Map<number, Set<number>>>();
  for (const sym of alphabet) {
    const symMap = new Map<number, Set<number>>();
    for (const sid of reachableIds) {
      const st = powersetDfa.states.get(sid)!;
      const tgt = st.transitions.get(sym) ?? (needsTrap ? TRAP_ID : undefined);
      if (tgt !== undefined) {
        if (!symMap.has(tgt)) symMap.set(tgt, new Set());
        symMap.get(tgt)!.add(sid);
      }
    }
    if (needsTrap) {
      if (!symMap.has(TRAP_ID)) symMap.set(TRAP_ID, new Set());
      symMap.get(TRAP_ID)!.add(TRAP_ID);
    }
    invTrans.set(sym, symMap);
  }

  let partitions: Set<number>[] = [];
  if (acceptIds.length > 0) partitions.push(new Set(acceptIds));
  if (nonAcceptIds.length > 0) partitions.push(new Set(nonAcceptIds));

  const worklist = new Map<string, { block: Set<number>; sym: string }>();
  const blockKey = (b: Iterable<number>, sym: string) =>
    `${Array.from(b).sort((a, c) => a - c).join(',')}::${sym}`;

  if (acceptIds.length > 0 && nonAcceptIds.length > 0) {
    const smaller = acceptIds.length <= nonAcceptIds.length ? acceptIds : nonAcceptIds;
    for (const sym of alphabet) {
      worklist.set(blockKey(smaller, sym), { block: new Set(smaller), sym });
    }
  } else if (partitions.length > 0) {
    for (const sym of alphabet) {
      worklist.set(blockKey(partitions[0], sym), { block: new Set(partitions[0]), sym });
    }
  }

  const hopcroftSteps: HopcroftSplitStep[] = [];
  // Initial step 0 snapshot
  hopcroftSteps.push({
    stepIndex: 0,
    splitterBlock: acceptIds,
    splitterSymbol: 'ε (Initial Split F vs Q\\F)',
    preimage: acceptIds,
    targetBlockBefore: [...acceptIds, ...nonAcceptIds.filter((id) => id !== TRAP_ID)],
    intersectionPart: acceptIds,
    differencePart: nonAcceptIds.filter((id) => id !== TRAP_ID),
    partitionsAfter: partitions
      .map((p) => Array.from(p).filter((id) => id !== TRAP_ID).sort((a, b) => a - b))
      .filter((arr) => arr.length > 0),
    worklistSizeAfter: worklist.size,
    explanation: `Initial partition P₀ splits states into Accepting F = {${acceptIds.map((i) => 'D' + i).join(', ')}} and Non-Accepting Q \\ F = {${nonAcceptIds.filter((i) => i !== TRAP_ID).map((i) => 'D' + i).join(', ')}}.`,
  });

  while (worklist.size > 0) {
    const firstKey = worklist.keys().next().value!;
    const { block: splitterBlock, sym } = worklist.get(firstKey)!;
    worklist.delete(firstKey);

    const symInv = invTrans.get(sym);
    const xPreimage = new Set<number>();
    if (symInv) {
      for (const tgt of splitterBlock) {
        const srcs = symInv.get(tgt);
        if (srcs) {
          srcs.forEach((s) => xPreimage.add(s));
        }
      }
    }
    if (xPreimage.size === 0) continue;

    const newPartitions: Set<number>[] = [];
    for (const block of partitions) {
      const intersection = new Set<number>();
      const difference = new Set<number>();
      for (const s of block) {
        if (xPreimage.has(s)) intersection.add(s);
        else difference.add(s);
      }

      if (intersection.size > 0 && difference.size > 0) {
        newPartitions.push(intersection);
        newPartitions.push(difference);

        for (const ch of alphabet) {
          const yKey = blockKey(block, ch);
          if (worklist.has(yKey)) {
            worklist.delete(yKey);
            worklist.set(blockKey(intersection, ch), { block: intersection, sym: ch });
            worklist.set(blockKey(difference, ch), { block: difference, sym: ch });
          } else {
            const smaller = intersection.size <= difference.size ? intersection : difference;
            worklist.set(blockKey(smaller, ch), { block: smaller, sym: ch });
          }
        }

        const cleanArr = (s: Set<number>) =>
          Array.from(s)
            .filter((id) => id !== TRAP_ID)
            .sort((a, b) => a - b);

        const intClean = cleanArr(intersection);
        const diffClean = cleanArr(difference);
        if (intClean.length > 0 && diffClean.length > 0) {
          hopcroftSteps.push({
            stepIndex: hopcroftSteps.length,
            splitterBlock: cleanArr(splitterBlock),
            splitterSymbol: sym,
            preimage: cleanArr(xPreimage),
            targetBlockBefore: cleanArr(block),
            intersectionPart: intClean,
            differencePart: diffClean,
            partitionsAfter: [...newPartitions, ...partitions.slice(partitions.indexOf(block) + 1)]
              .map(cleanArr)
              .filter((arr) => arr.length > 0),
            worklistSizeAfter: worklist.size,
            explanation: `Splitter ({${cleanArr(splitterBlock).map((i) => 'D' + i).join(', ')}}, '${sym}') has preimage X = {${cleanArr(xPreimage).map((i) => 'D' + i).join(', ')}} which fractures block {${cleanArr(block).map((i) => 'D' + i).join(', ')}} into Y₁ = {${intClean.map((i) => 'D' + i).join(', ')}} and Y₂ = {${diffClean.map((i) => 'D' + i).join(', ')}}.`,
          });
        }
      } else {
        newPartitions.push(block);
      }
    }
    partitions = newPartitions;
  }

  // Synthesize Quotient Minimal DFA with Canonical BFS Relabeling
  const activeBlocks = partitions
    .map((b) => Array.from(b).filter((id) => id !== TRAP_ID).sort((a, b) => a - b))
    .filter((b) => b.length > 0);

  const stateToBlockIdx = new Map<number, number>();
  activeBlocks.forEach((b, idx) => {
    b.forEach((sid) => stateToBlockIdx.set(sid, idx));
  });

  const startBlockIdx = stateToBlockIdx.get(powersetDfa.startStateId) ?? 0;

  // Canonical BFS ordering of blocks
  const canonicalMap = new Map<number, number>([[startBlockIdx, 0]]);
  const bfsQueue: number[] = [startBlockIdx];
  let nextCanonicalId = 1;

  while (bfsQueue.length > 0) {
    const currB = bfsQueue.shift()!;
    const repSid = activeBlocks[currB][0];
    const repState = powersetDfa.states.get(repSid)!;

    for (const mt of powersetDfa.minterms) {
      const origTarget = repState.transitions.get(mt.label);
      if (origTarget !== undefined) {
        const targetB = stateToBlockIdx.get(origTarget);
        if (targetB !== undefined && !canonicalMap.has(targetB)) {
          canonicalMap.set(targetB, nextCanonicalId++);
          bfsQueue.push(targetB);
        }
      }
    }
  }

  for (let bIdx = 0; bIdx < activeBlocks.length; bIdx++) {
    if (!canonicalMap.has(bIdx)) {
      canonicalMap.set(bIdx, nextCanonicalId++);
    }
  }

  const minStates = new Map<number, DFAStateData>();
  for (const [oldBIdx, newSid] of canonicalMap.entries()) {
    const dSubset = activeBlocks[oldBIdx];
    const nfaSet = new Set<number>();
    let isAccept = false;
    for (const did of dSubset) {
      const dSt = powersetDfa.states.get(did)!;
      if (dSt.isAccept) isAccept = true;
      dSt.nfaStateIds.forEach((q) => nfaSet.add(q));
    }

    minStates.set(newSid, {
      id: newSid,
      name: `M${newSid}`,
      isStart: newSid === 0,
      isAccept,
      nfaStateIds: Array.from(nfaSet).sort((a, b) => a - b),
      powersetStateIds: dSubset,
      transitions: new Map(),
      charTransitions: new Map(),
    });
  }

  for (const [oldBIdx, newSid] of canonicalMap.entries()) {
    const mState = minStates.get(newSid)!;
    const repState = powersetDfa.states.get(activeBlocks[oldBIdx][0])!;
    for (const mt of powersetDfa.minterms) {
      const origTarget = repState.transitions.get(mt.label);
      if (origTarget !== undefined) {
        const targetB = stateToBlockIdx.get(origTarget);
        if (targetB !== undefined) {
          const targetNewSid = canonicalMap.get(targetB)!;
          mState.transitions.set(mt.label, targetNewSid);
          for (const ch of mt.chars) {
            mState.charTransitions.set(ch, targetNewSid);
          }
        }
      }
    }
  }

  const minimalDfa: CompiledDFA = {
    kind: 'MINIMAL',
    startStateId: 0,
    states: minStates,
    minterms: powersetDfa.minterms,
    alphabetLabels: powersetDfa.alphabetLabels,
  };

  const myhillNerodeTable = computeMyhillNerodeTable(powersetDfa);

  return {
    minimalDfa,
    hopcroftSteps,
    myhillNerodeTable,
  };
}

/**
 * Computes the Myhill-Nerode Pairwise Distinguishability Table with shortest distinguishing suffix w
 * for every pair of Powerset DFA states (D_i, D_j) where i < j.
 */
function computeMyhillNerodeTable(dfa: CompiledDFA): MyhillNerodeCell[] {
  const sids = Array.from(dfa.states.keys()).sort((a, b) => a - b);
  const TRAP = -1;
  const allIds = [...sids, TRAP];

  const isAccept = (id: number) => (id === TRAP ? false : dfa.states.get(id)!.isAccept);
  const step = (id: number, sampleChar: string): number => {
    if (id === TRAP) return TRAP;
    return dfa.states.get(id)!.charTransitions.get(sampleChar) ?? TRAP;
  };

  const pairKey = (a: number, b: number) => (a < b ? `${a}_${b}` : `${b}_${a}`);
  const suffixMap = new Map<string, { suffix: string; round: number }>();

  // Round 0: Accepting vs Non-accepting
  for (let i = 0; i < allIds.length; i++) {
    for (let j = i + 1; j < allIds.length; j++) {
      const a = allIds[i];
      const b = allIds[j];
      if (isAccept(a) !== isAccept(b)) {
        suffixMap.set(pairKey(a, b), { suffix: 'ε', round: 0 });
      }
    }
  }

  let changed = true;
  let round = 1;
  while (changed) {
    changed = false;
    for (let i = 0; i < allIds.length; i++) {
      for (let j = i + 1; j < allIds.length; j++) {
        const a = allIds[i];
        const b = allIds[j];
        const pk = pairKey(a, b);
        if (suffixMap.has(pk)) continue;

        for (const mt of dfa.minterms) {
          const nextA = step(a, mt.sampleChar);
          const nextB = step(b, mt.sampleChar);
          if (nextA === nextB) continue;
          const nextEntry = suffixMap.get(pairKey(nextA, nextB));
          if (nextEntry) {
            const sub = nextEntry.suffix === 'ε' ? '' : nextEntry.suffix;
            suffixMap.set(pk, {
              suffix: `${mt.sampleChar}${sub}`,
              round,
            });
            changed = true;
            break;
          }
        }
      }
    }
    round++;
  }

  const cells: MyhillNerodeCell[] = [];
  for (let i = 0; i < sids.length; i++) {
    for (let j = i + 1; j < sids.length; j++) {
      const a = sids[i];
      const b = sids[j];
      const entry = suffixMap.get(pairKey(a, b));
      cells.push({
        stateA: a,
        stateB: b,
        distinguishable: Boolean(entry),
        witnessSuffix: entry ? entry.suffix : null,
        roundIdentified: entry ? entry.round : -1,
      });
    }
  }
  return cells;
}

// ============================================================================
// Static ReDoS & Nondeterministic Ambiguity Analyzer
// ============================================================================

function analyzeRedosRisk(ast: ASTNode, nfa: CompiledNFA, minimalDfa: CompiledDFA): RedosAnalysis {
  let maxStarDepth = 0;
  let hasOverlappingAlternationInStar = false;

  function checkDepth(node: ASTNode, depth: number) {
    const isLoop =
      node.kind === 'Star' ||
      node.kind === 'Plus' ||
      (node.kind === 'Repeat' && (node.maxRepeat === null || (node.maxRepeat ?? 0) > 1));
    const nextDepth = isLoop ? depth + 1 : depth;
    if (nextDepth > maxStarDepth) maxStarDepth = nextDepth;

    if (isLoop && node.children[0]?.kind === 'Union') {
      hasOverlappingAlternationInStar = true;
    }
    node.children.forEach((c) => checkDepth(c, nextDepth));
  }
  checkDepth(ast, 0);

  let branchingStates = 0;
  for (const st of nfa.states.values()) {
    if (st.transitions.length > 1) branchingStates++;
  }

  // Generate sample witness char from minimal DFA
  const sampleRepeatChar = minimalDfa.minterms[0]?.sampleChar ?? 'a';

  if (maxStarDepth >= 2 || hasOverlappingAlternationInStar) {
    return {
      riskLevel: 'IMMUNE (O(|w|) DFA)',
      backtrackerRisk: 'CRITICAL',
      starHeight: maxStarDepth,
      nondeterministicBranching: branchingStates,
      explanation: `Nested quantifier star-height ${maxStarDepth} causes O(2^|w|) catastrophic backtracking in PCRE/Python 're'. FINIX Ω compiles this into a ${minimalDfa.states.size}-state Minimal DFA with guaranteed O(|w|) single-pass execution.`,
      evilPayloadSample: `${sampleRepeatChar.repeat(28)}!`,
    };
  }

  if (maxStarDepth === 1 && branchingStates >= 3) {
    return {
      riskLevel: 'IMMUNE (O(|w|) DFA)',
      backtrackerRisk: 'MEDIUM',
      starHeight: maxStarDepth,
      nondeterministicBranching: branchingStates,
      explanation: `Quantified pattern with ${branchingStates} non-deterministic branching states can exhibit O(|w|²) polynomial backtracking in naive engines. Determinized to ${minimalDfa.states.size} states in FINIX Ω.`,
      evilPayloadSample: `${sampleRepeatChar.repeat(24)}X`,
    };
  }

  return {
    riskLevel: 'IMMUNE (O(|w|) DFA)',
    backtrackerRisk: 'LOW',
    starHeight: maxStarDepth,
    nondeterministicBranching: branchingStates,
    explanation: `Linear star-height (${maxStarDepth}) and deterministic ${minimalDfa.states.size}-state Minimal DFA guarantee strict O(|w|) time complexity with zero backtracking stack.`,
    evilPayloadSample: null,
  };
}

// ============================================================================
// Master Regex Compiler Pipeline
// ============================================================================

export function compileRegexPipeline(regexStr: string): RegexCompilationResult {
  const t0 = performance.now();
  const { tokens, isAnchoredStart, isAnchoredEnd, normalizedRegex } = tokenizeRegex(regexStr);
  const concatTokens = insertExplicitConcat(tokens);
  const postfixTokens = infixToPostfix(concatTokens);
  const postfixString = postfixTokens.map((t) => t.value).join(' ');
  const ast = buildAST(postfixTokens);
  const minterms = computeMintermsFromAST(ast);
  const nfa = buildThompsonNFAFromAST(ast, minterms);
  const powersetDfa = determinizeNFA(nfa, minterms);
  const { minimalDfa, hopcroftSteps, myhillNerodeTable } = minimizeDFAWithTrace(powersetDfa);
  const redosAnalysis = analyzeRedosRisk(ast, nfa, minimalDfa);
  const compileTimeMs = performance.now() - t0;

  return {
    regex: regexStr,
    normalizedRegex,
    isAnchoredStart,
    isAnchoredEnd,
    rawTokens: tokens,
    concatTokens,
    postfixTokens,
    postfixString,
    ast,
    minterms,
    nfa,
    powersetDfa,
    minimalDfa,
    hopcroftSteps,
    myhillNerodeTable,
    redosAnalysis,
    compileTimeMs,
  };
}

// ============================================================================
// Dual-Track Synchronized Simulator (ε-NFA + Powerset DFA + Minimal DFA)
// ============================================================================

export function simulateDualExecution(
  compiled: RegexCompilationResult,
  input: string
): DualSimulationResult {
  const t0 = performance.now();
  const { nfa, powersetDfa, minimalDfa, minterms } = compiled;

  let currNfaStates = computeEpsilonClosure(nfa, [nfa.startStateId]);
  const nfaInitialStates = Array.from(currNfaStates).sort((a, b) => a - b);

  let currPowersetState: number | null = powersetDfa.startStateId;
  let currMinimalState: number | null = minimalDfa.startStateId;

  const steps: DualTraceStep[] = [];

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    const beforeNfa = Array.from(currNfaStates).sort((a, b) => a - b);
    const directSet = computeMove(nfa, currNfaStates, ch);
    const afterSet = computeEpsilonClosure(nfa, directSet);
    const epsAdd = Array.from(afterSet)
      .filter((id) => !directSet.has(id))
      .sort((a, b) => a - b);

    const nextPowerset: number | null =
      currPowersetState !== null
        ? (powersetDfa.states.get(currPowersetState)?.charTransitions.get(ch) ?? null)
        : null;

    const nextMinimal: number | null =
      currMinimalState !== null
        ? (minimalDfa.states.get(currMinimalState)?.charTransitions.get(ch) ?? null)
        : null;

    const matchedMt = minterms.find((m) => m.chars.has(ch))?.label ?? `Unmapped ('${ch}')`;

    const nfaAcceptsHere = Array.from(afterSet).some((id) => nfa.states.get(id)?.isAccept);
    const dfaAcceptsHere =
      nextMinimal !== null ? Boolean(minimalDfa.states.get(nextMinimal)?.isAccept) : false;

    steps.push({
      stepIndex: i + 1,
      char: ch,
      nfaBefore: beforeNfa,
      nfaDirectMove: Array.from(directSet).sort((a, b) => a - b),
      nfaEpsilonAdditions: epsAdd,
      nfaAfter: Array.from(afterSet).sort((a, b) => a - b),
      powersetBefore: currPowersetState,
      powersetAfter: nextPowerset,
      minimalBefore: currMinimalState,
      minimalAfter: nextMinimal,
      nfaAcceptsHere,
      dfaAcceptsHere,
      matchedMintermLabel: matchedMt,
    });

    currNfaStates = afterSet;
    currPowersetState = nextPowerset;
    currMinimalState = nextMinimal;
  }

  const elapsedMs = performance.now() - t0;
  const isAccepted =
    currMinimalState !== null
      ? Boolean(minimalDfa.states.get(currMinimalState)?.isAccept)
      : Array.from(currNfaStates).some((id) => nfa.states.get(id)?.isAccept);

  return {
    input,
    isAccepted,
    nfaInitialStates,
    nfaFinalStates: Array.from(currNfaStates).sort((a, b) => a - b),
    powersetInitialState: powersetDfa.startStateId,
    powersetFinalState: currPowersetState,
    minimalInitialState: minimalDfa.startStateId,
    minimalFinalState: currMinimalState,
    steps,
    elapsedMs,
  };
}

// ============================================================================
// Automated Equivalence Prover & Shortest Counterexample Witness Generator
// ============================================================================

export function proveRegexEquivalence(regex1: string, regex2: string): EquivalenceProofResult {
  const compiled1 = compileRegexPipeline(regex1);
  const compiled2 = compileRegexPipeline(regex2);

  const dfa1 = compiled1.minimalDfa;
  const dfa2 = compiled2.minimalDfa;

  const TRAP = -1;
  const isAcc1 = (s: number) => (s === TRAP ? false : Boolean(dfa1.states.get(s)?.isAccept));
  const isAcc2 = (s: number) => (s === TRAP ? false : Boolean(dfa2.states.get(s)?.isAccept));

  const step1 = (s: number, ch: string) =>
    s === TRAP ? TRAP : (dfa1.states.get(s)?.charTransitions.get(ch) ?? TRAP);
  const step2 = (s: number, ch: string) =>
    s === TRAP ? TRAP : (dfa2.states.get(s)?.charTransitions.get(ch) ?? TRAP);

  // Collect unified representative characters across both automata's minterms
  const repCharsSet = new Set<string>();
  compiled1.minterms.forEach((m) => repCharsSet.add(m.sampleChar));
  compiled2.minterms.forEach((m) => repCharsSet.add(m.sampleChar));
  const repChars = Array.from(repCharsSet).sort();

  // BFS over Product Automaton (Q1 U {TRAP}) x (Q2 U {TRAP})
  const visited = new Set<string>();
  const queue: { s1: number; s2: number; word: string }[] = [
    { s1: dfa1.startStateId, s2: dfa2.startStateId, word: '' },
  ];
  visited.add(`${dfa1.startStateId}_${dfa2.startStateId}`);

  let witness1Minus2: string | null = null;
  let witness2Minus1: string | null = null;
  let witnessIntersection: string | null = null;

  while (queue.length > 0) {
    const { s1, s2, word } = queue.shift()!;
    const a1 = isAcc1(s1);
    const a2 = isAcc2(s2);

    if (a1 && !a2 && witness1Minus2 === null) {
      witness1Minus2 = word;
    }
    if (!a1 && a2 && witness2Minus1 === null) {
      witness2Minus1 = word;
    }
    if (a1 && a2 && witnessIntersection === null) {
      witnessIntersection = word;
    }

    if (witness1Minus2 !== null && witness2Minus1 !== null && witnessIntersection !== null) {
      break;
    }

    for (const ch of repChars) {
      const n1 = step1(s1, ch);
      const n2 = step2(s2, ch);
      if (n1 === TRAP && n2 === TRAP) continue;
      const key = `${n1}_${n2}`;
      if (!visited.has(key)) {
        visited.add(key);
        queue.push({ s1: n1, s2: n2, word: word + ch });
      }
    }
  }

  const isSubset1Of2 = witness1Minus2 === null;
  const isSubset2Of1 = witness2Minus1 === null;
  const isEquivalent = isSubset1Of2 && isSubset2Of1;
  const isDisjoint = witnessIntersection === null;

  let relationSummary: EquivalenceProofResult['relationSummary'] = 'OVERLAPPING (L₁ ≉ L₂)';
  if (isEquivalent) {
    relationSummary = 'EQUIVALENT (L₁ ≡ L₂)';
  } else if (isSubset1Of2 && !isSubset2Of1) {
    relationSummary = 'STRICT SUBSET (L₁ ⊂ L₂)';
  } else if (!isSubset1Of2 && isSubset2Of1) {
    relationSummary = 'STRICT SUPERSET (L₁ ⊃ L₂)';
  } else if (isDisjoint) {
    relationSummary = 'DISJOINT (L₁ ∩ L₂ = ∅)';
  }

  const formalProofSteps: string[] = [
    `1. Synthesized Minimal DFA M₁ for r₁ ('${regex1}'): |Q₁| = ${dfa1.states.size} canonical states.`,
    `2. Synthesized Minimal DFA M₂ for r₂ ('${regex2}'): |Q₂| = ${dfa2.states.size} canonical states.`,
    `3. Constructed Product Automaton M₁ × M₂ over ${repChars.length} joint equivalence classes (${visited.size} product states explored).`,
  ];

  if (isEquivalent) {
    formalProofSteps.push(
      `4. Symmetric Difference L(M₁) ⊕ L(M₂) = (L₁ \\ L₂) ∪ (L₂ \\ L₁) = ∅. By the Myhill-Nerode Theorem, M₁ ≅ M₂ up to alphabet partition isomorphism.`
    );
  } else {
    if (witness1Minus2 !== null) {
      formalProofSteps.push(
        `4a. Difference L₁ \\ L₂ ≠ ∅: Lexicographically shortest counterexample w = ${witness1Minus2 === '' ? 'ε (empty string)' : `"${witness1Minus2}"`} ∈ L(r₁) \\ L(r₂).`
      );
    } else {
      formalProofSteps.push(`4a. Inclusion L₁ ⊆ L₂ holds (L₁ \\ L₂ = ∅).`);
    }
    if (witness2Minus1 !== null) {
      formalProofSteps.push(
        `4b. Difference L₂ \\ L₁ ≠ ∅: Lexicographically shortest counterexample w = ${witness2Minus1 === '' ? 'ε (empty string)' : `"${witness2Minus1}"`} ∈ L(r₂) \\ L(r₁).`
      );
    } else {
      formalProofSteps.push(`4b. Inclusion L₂ ⊆ L₁ holds (L₂ \\ L₁ = ∅).`);
    }
  }

  return {
    regex1,
    regex2,
    isEquivalent,
    isSubset1Of2,
    isSubset2Of1,
    isDisjoint,
    relationSummary,
    witness1Minus2,
    witness2Minus1,
    witnessIntersection,
    compiled1,
    compiled2,
    formalProofSteps,
  };
}

// ============================================================================
// Curated Compiler Presets
// ============================================================================

export interface CompilerPreset {
  id: string;
  name: string;
  category: 'Classic TOC' | 'Extended Algebra' | 'Security Signature' | 'ReDoS Stress';
  regex: string;
  sampleAccept: string;
  sampleReject: string;
  description: string;
}

export const COMPILER_PRESETS: CompilerPreset[] = [
  {
    id: 'toc-abb',
    name: 'Dragon Book Canonical (a|b)*abb',
    category: 'Classic TOC',
    regex: '(a|b)*abb',
    sampleAccept: 'ababb',
    sampleReject: 'ababa',
    description: 'Aho-Sethi-Ullman Dragon Book benchmark demonstrating Hopcroft state reduction from Powerset DFA to 4-state Minimal DFA.',
  },
  {
    id: 'ext-quant',
    name: 'Bounded Quantifier & Class a{2,4}[0-9]+',
    category: 'Extended Algebra',
    regex: 'a{2,4}[0-9]+',
    sampleAccept: 'aaa42',
    sampleReject: 'a42',
    description: 'Demonstrates bounded repetition {n,m} lowering and minterm equivalence class compression for [0-9].',
  },
  {
    id: 'ext-intersect',
    name: 'Boolean Intersection & Complement',
    category: 'Extended Algebra',
    regex: '(a|b)+&~(.*bb.*)',
    sampleAccept: 'abababa',
    sampleReject: 'ababb',
    description: 'All non-empty strings over {a,b} that never contain two consecutive b characters, compiled via product intersection and complement.',
  },
  {
    id: 'sec-exe',
    name: 'Binary Download URI Signature',
    category: 'Security Signature',
    regex: '(http|https)://[a-z0-9.-]+\\.(exe|sh|bat)',
    sampleAccept: 'https://cdn.payload-drop.io/install.sh',
    sampleReject: 'https://cdn.payload-drop.io/index.html',
    description: 'Detects executable binary or shell script downloads over HTTP/HTTPS.',
  },
  {
    id: 'redos-nested',
    name: 'Pathological ReDoS Trap (a+)+b',
    category: 'ReDoS Stress',
    regex: '(a+)+b',
    sampleAccept: 'aaaaab',
    sampleReject: 'aaaaaaaaaaaaaaaaaaaa!',
    description: 'Triggers O(2^n) catastrophic backtracking in PCRE/Python re on rejecting strings, yet runs in 0.01ms O(|w|) time via FINIX Ω Minimal DFA.',
  },
];
