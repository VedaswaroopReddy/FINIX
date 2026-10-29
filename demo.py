"""
demo.py: Interactive Terminal Showcase for the FINIX Automata Engine.
Demonstrates the full theoretical hierarchy from first principles:
  1. Lexer, Explicit Concatenation (·), and Extended AST
  2. Thompson Inductive ε-NFA Construction
  3. Rabin-Scott Powerset Determinization (DFA)
  4. Hopcroft Canonical State Minimization
  5. Myhill-Nerode Language Equivalence Theorem Prover
  6. Single-Pass SIEM Multi-Signature Master DFA
  7. Empirical ReDoS Immunity Verification
"""

import sys
import os
import time

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except (AttributeError, ValueError, OSError) as _err:
        sys.stderr.write(f"Notice: stdout reconfigure unavailable: {_err}\n")
if hasattr(sys.stderr, 'reconfigure'):
    try:
        sys.stderr.reconfigure(encoding='utf-8')
    except (AttributeError, ValueError, OSError) as _err:
        sys.stderr.write(f"Notice: stderr reconfigure unavailable: {_err}\n")

from regex_nfa.parser import parse_regex, format_postfix, build_ast, tokenize, insert_explicit_concat
from regex_nfa.thompson import compile_regex
from regex_nfa.dfa import nfa_to_dfa
from regex_nfa.minimizer import minimize_dfa, are_equivalent_regexes
from regex_nfa.simulator import NFASimulator
from regex_nfa.visualizer import Visualizer
from regex_nfa.scanner import SIEMLogScanner
from regex_nfa.benchmarks import ReDoSBenchmarkSuite


class Color:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'


def banner():
    print(f"{Color.CYAN}{Color.BOLD}" + "=" * 78)
    print("         FINIX: Formally Verified Automata & ReDoS Mitigation Platform")
    print("               First-Principles Theory of Computation Suite")
    print("=" * 78 + f"{Color.END}")


def run_pipeline_demo(regex: str, test_inputs: list):
    print(f"\n{Color.BOLD}{Color.HEADER}" + "=" * 78)
    print(f" DEMO CASE: COMPILING REGEX '/{regex}/'")
    print("=" * 78 + f"{Color.END}")

    # 1. Lexer & AST
    raw_tokens = tokenize(regex)
    concat_tokens = insert_explicit_concat(raw_tokens)
    postfix_tokens = parse_regex(regex)
    ast = build_ast(postfix_tokens)

    print(f"{Color.BOLD}1. Syntax Layer:{Color.END}")
    print(f"   • Explicit Concat Form (·) : {' '.join(t.value for t in concat_tokens)}")
    print(f"   • Reverse Polish (RPN)     : {format_postfix(postfix_tokens)}")
    print(f"   • Abstract Syntax Tree     : {Color.YELLOW}{ast.to_string() if ast else 'empty()'}{Color.END}")

    # 2. Thompson ε-NFA
    t0 = time.perf_counter()
    nfa = compile_regex(regex)
    nfa_ms = (time.perf_counter() - t0) * 1000
    metrics = nfa.get_metrics()
    print(f"\n{Color.BOLD}2. Tier 1 — Thompson ε-NFA (compiled in {nfa_ms:.3f} ms):{Color.END}")
    print(f"   • States |Q_N|             : {metrics['state_count']} (Theoretical Bound: <= 2|r|)")
    print(f"   • Transitions |δ_N|        : {metrics['transition_count']} ({metrics['epsilon_transition_count']} ε-moves)")
    print(f"   • Start / Accept States    : Start q{nfa.start_state.id} -> Accept q{nfa.accept_state.id}")

    # 3. Rabin-Scott Powerset DFA
    t0 = time.perf_counter()
    dfa = nfa_to_dfa(nfa)
    dfa_ms = (time.perf_counter() - t0) * 1000
    dfa_metrics = dfa.get_metrics()
    print(f"\n{Color.BOLD}3. Tier 2 — Rabin-Scott Powerset DFA (synthesized in {dfa_ms:.3f} ms):{Color.END}")
    print(f"   • Powerset States |Q_D|    : {dfa_metrics['state_count']}")
    print(f"   • Transitions |δ_D|        : {dfa_metrics['transition_count']}")
    print(f"   • Start State              : {dfa_metrics['start_state']}")
    print(f"   • Accept States            : {dfa_metrics['accept_states']}")

    # 4. Hopcroft Canonical Minimization
    t0 = time.perf_counter()
    min_dfa = minimize_dfa(dfa)
    min_ms = (time.perf_counter() - t0) * 1000
    min_metrics = min_dfa.get_metrics()
    reduction = ((len(dfa.states) - len(min_dfa.states)) / len(dfa.states)) * 100 if dfa.states else 0
    print(f"\n{Color.BOLD}4. Tier 3 — Hopcroft Canonical Minimal DFA (minimized in {min_ms:.3f} ms):{Color.END}")
    print(f"   • Minimal States |Q_M|     : {min_metrics['state_count']}")
    print(f"   • State Reduction Ratio    : {reduction:.1f}% reduction")
    print(f"   • Start State              : {min_metrics['start_state']}")
    print(f"   • Accept States            : {min_metrics['accept_states']}")

    # 5. Differential Parity Matching Across All 3 Tiers
    print(f"\n{Color.BOLD}5. Differential Parity Execution:{Color.END}")
    sim_nfa = NFASimulator(nfa)
    for text, expected in test_inputs:
        nfa_res = sim_nfa.simulate(text)
        dfa_res = dfa.match(text)
        min_res = min_dfa.match(text)

        parity = (nfa_res.is_accepted == dfa_res == min_res)
        parity_str = f"{Color.GREEN}PARITY OK{Color.END}" if parity else f"{Color.RED}PARITY MISMATCH{Color.END}"
        verdict = f"{Color.GREEN}ACCEPTED{Color.END}" if min_res else f"{Color.RED}REJECTED{Color.END}"
        display_str = f"'{text}'" if text != "" else "ε (empty string)"

        print(f"   • Input: {display_str:<22} -> {verdict:<18} [NFA={nfa_res.is_accepted}, DFA={dfa_res}, MinDFA={min_res}] ({parity_str})")


def run_equivalence_demo():
    print(f"\n{Color.BOLD}{Color.HEADER}" + "=" * 78)
    print(" DEMO: MYHILL-NERODE LANGUAGE EQUIVALENCE THEOREM PROVER")
    print("=" * 78 + f"{Color.END}")

    pairs = [
        ("a+", "aa*", True, "Kleene Star Unrolling"),
        ("(a|b)*", "(a*b*)*", True, "Star Sliding Identity"),
        ("(a|b)*abb", "(a|b)*ab", False, "Different Language Suffix"),
    ]

    for r1, r2, expected_eq, label in pairs:
        is_eq, msg = are_equivalent_regexes(r1, r2)
        status = f"{Color.GREEN}PASS{Color.END}" if is_eq == expected_eq else f"{Color.RED}FAIL{Color.END}"
        relation = f"{Color.GREEN}L({r1}) ≡ L({r2}){Color.END}" if is_eq else f"{Color.YELLOW}L({r1}) ≢ L({r2}){Color.END}"
        print(f"\n[*] Case: {label}")
        print(f"    Comparing: r1='{r1}' vs r2='{r2}'")
        print(f"    Verdict  : {relation} ({status})")
        print(f"    Proof    : {msg}")


def run_siem_demo():
    print(f"\n{Color.BOLD}{Color.HEADER}" + "=" * 78)
    print(" DEMO: SINGLE-PASS SIEM MULTI-PATTERN MASTER DFA SCANNER")
    print("=" * 78 + f"{Color.END}")

    scanner = SIEMLogScanner()
    print(f"[*] Loaded {len(scanner.rules)} security rules into unified Master DFA.")

    test_payloads = [
        ("GET /search?id=1' or 1=1-- HTTP/1.1", "SQL Injection"),
        ("GET /public/documents/../../etc/passwd HTTP/1.1", "Path Traversal"),
        ("GET /comment?q=<script>alert(1)</script> HTTP/1.1", "XSS Injection"),
        ("GET /api/v1/products?category=electronics HTTP/1.1", "Benign API Call"),
    ]

    print("\n[+] Single-Pass Stream Inspection:")
    for payload, desc in test_payloads:
        matches = scanner.master_dfa.scan_target(payload)
        if matches:
            hit_tags = ", ".join(f"[{m.id}] {m.name}" for m in matches)
            print(f" {Color.RED}[THREAT DETECTED - {matches[0].threat_level}]{Color.END} {desc}")
            print(f"   Payload: {payload}")
            print(f"   Triggered Rules: {Color.CYAN}{hit_tags}{Color.END}")
        else:
            print(f" {Color.GREEN}[CLEAN / BENIGN]{Color.END} {desc}")
            print(f"   Payload: {payload}")


def run_redos_demo():
    print(f"\n{Color.BOLD}{Color.HEADER}" + "=" * 78)
    print(" DEMO: EMPIRICAL REDOS IMMUNITY HARNESS")
    print("=" * 78 + f"{Color.END}")

    suite = ReDoSBenchmarkSuite(timeout_sec=1.0)
    print("[*] Running nested quantifier ReDoS benchmark: (a+)+b against 'a'*n + '!'\n")
    report = suite.run_benchmark("TAXONOMY_1", lengths=[6, 10, 14, 18, 22])
    print(report["ascii_table"])


def interactive_mode():
    banner()
    print(f"{Color.CYAN}Interactive First-Principles Regex Compiler & Stepper{Color.END}")
    print("Type 'exit' or 'q' to quit.\n")

    while True:
        try:
            regex = input(f"{Color.BOLD}Enter Regular Expression:{Color.END} ").strip()
            if not regex:
                continue
            if regex.lower() in {'exit', 'q', 'quit'}:
                print("Exiting.")
                break

            postfix = parse_regex(regex)
            print(f"  {Color.BOLD}Postfix (RPN) :{Color.END} {format_postfix(postfix)}")

            nfa = compile_regex(regex)
            dfa = nfa_to_dfa(nfa)
            min_dfa = minimize_dfa(dfa)

            print(f"  {Color.BOLD}NFA States    :{Color.END} {len(nfa.states)} states (Thompson)")
            print(f"  {Color.BOLD}Powerset DFA  :{Color.END} {len(dfa.states)} states (Rabin-Scott)")
            print(f"  {Color.BOLD}Minimal DFA   :{Color.END} {len(min_dfa.states)} states (Hopcroft)")

            print(f"\n{Color.BOLD}Canonical Minimal Transition Table:{Color.END}")
            print(min_dfa.generate_transition_table())

            print(f"\n{Color.CYAN}Enter test strings (type 'done' to change regex):{Color.END}")
            while True:
                test_str = input("  Test String: ")
                if test_str.lower() in {'done', 'back'}:
                    break
                accepted = min_dfa.match(test_str)
                if accepted:
                    print(f"  -> {Color.GREEN}{Color.BOLD}ACCEPTED{Color.END} ✓ (O(|w|) Linear DFA)")
                else:
                    print(f"  -> {Color.RED}{Color.BOLD}REJECTED{Color.END} ✗ (O(|w|) Linear DFA)")

            print("\n" + "=" * 78 + "\n")

        except Exception as e:
            print(f"{Color.RED}Error: {e}{Color.END}\n")


def main():
    if len(sys.argv) > 1 and sys.argv[1] in {"--interactive", "-i"}:
        interactive_mode()
    else:
        banner()
        # Case 1: Textbook pattern
        run_pipeline_demo(
            regex="(a|b)*abb",
            test_inputs=[
                ("abb", True),
                ("aabb", True),
                ("ababb", True),
                ("babb", True),
                ("ab", False),
                ("abba", False),
                ("", False),
            ]
        )
        # Case 2: Extended Grammar
        run_pipeline_demo(
            regex="a+b?",
            test_inputs=[
                ("a", True),
                ("ab", True),
                ("aaaaab", True),
                ("b", False),
                ("", False),
            ]
        )
        # Equivalence Prover
        run_equivalence_demo()
        # SIEM Scanner
        run_siem_demo()
        # ReDoS Immunity
        run_redos_demo()

        print(f"\n{Color.CYAN}Tip: Run `python demo.py --interactive` for live interactive prompt!{Color.END}\n")


if __name__ == '__main__':
    main()
