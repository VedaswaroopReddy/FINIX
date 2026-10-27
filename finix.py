#!/usr/bin/env python3
"""
finix.py: Unified Command-Line Interface (CLI) for FINIX Automata & Security Engine.

Commands:
  finix compile     Compile regex to Thompson ε-NFA with AST & metrics.
  finix dfa         Construct Rabin-Scott Powerset DFA with fast transition table.
  finix minimize    Synthesize Hopcroft Canonical Minimal DFA.
  finix match       Evaluate string against all 3 automata tiers with execution traces.
  finix equivalent  Prove formal language equivalence L(r1) ≡ L(r2) via DFA isomorphism.
  finix benchmark   Run empirical ReDoS benchmark suite vs. Python 're' with SVG plot export.
  finix scan        Execute high-throughput SIEM multi-signature scanner on logs or payloads.
  finix serve       Launch interactive dual/triple automata web visualizer and REST server.
"""

import sys
import os
import argparse
import time
import re

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from regex_nfa import (
    compile_regex,
    compile_to_dfa,
    are_equivalent_regexes,
    NFASimulator,
    ReDoSBenchmarkSuite,
    BENCHMARK_TAXONOMIES,
    SIEMLogScanner,
)
from regex_nfa.parser import parse_regex


def format_compile_error(regex: str, err: Exception) -> str:
    err_str = str(err)
    pos_match = re.search(r'position\s+(\d+)', err_str, re.IGNORECASE)
    pos = int(pos_match.group(1)) if pos_match else None
    spaced_pattern = " ".join(list(regex))

    if "range" in err_str.lower() and "out of order" in err_str.lower():
        caret_pos = (pos * 2) if pos is not None else 0
        caret_line = " " * caret_pos + "^~~~^"
        return (
            f"[-] Compilation Error: Syntax Error at Position {pos if pos is not None else 1}\n"
            f"    Pattern:  {spaced_pattern}\n"
            f"              {caret_line}\n"
            f"    Details: {err_str}"
        )
    elif "parenthesis" in err_str.lower() or "parentheses" in err_str.lower():
        pos_val = len(regex) if pos is None else pos
        caret_pos = pos_val * 2
        caret_line = " " * caret_pos + "^ (Expected closing ')')\n"
        return (
            f"[-] Compilation Error: Mismatched Parentheses at Position {pos_val}\n"
            f"    Pattern:  {spaced_pattern}\n"
            f"              {caret_line}"
            f"    Details: {err_str}"
        )
    elif pos is not None:
        caret_pos = pos * 2
        caret_line = " " * caret_pos + "^\n"
        return (
            f"[-] Compilation Error: Syntax Error at Position {pos}\n"
            f"    Pattern:  {spaced_pattern}\n"
            f"              {caret_line}"
            f"    Details: {err_str}"
        )
    else:
        return f"[-] Compilation Error: {err_str}"


def cmd_compile(args):
    """Compiles regex to Thompson ε-NFA and outputs formal TOC metrics."""
    regex = getattr(args, 'regex_flag', None) or args.regex
    if not regex:
        print("[-] Error: Argument 'regex' is required (e.g. finix compile 'a*' or finix compile --regex 'a*')", file=sys.stderr)
        sys.exit(1)
    print(f"\n[+] Compiling regular expression: '{regex}'")
    try:
        t0 = time.perf_counter()
        postfix = parse_regex(regex)
        nfa = compile_regex(regex)
        dt = (time.perf_counter() - t0) * 1000.0

        rpn_str = " ".join(t.value for t in postfix)
        print(f"[*] Reverse Polish Notation (RPN): {rpn_str}")

        m = nfa.get_metrics()
        print(f"[*] Thompson ε-NFA compiled in {dt:.3f} ms")
        print(f"    - States |Q_N|:       {m['state_count']} (Theoretical bound: <= 2|r|)")
        print(f"    - Transitions |δ_N|:  {m['transition_count']}")
        print(f"    - ε-Transitions:      {m['epsilon_transition_count']}")
        print(f"    - Alphabet Σ:         {nfa.get_alphabet()}")
        print(f"    - Start State:        {m['start_state']}")
        print(f"    - Accept State:       {m['accept_state']}")

        if args.table:
            print("\nFormal Transition Table δ:")
            print(nfa.generate_transition_table())

    except Exception as e:
        print(format_compile_error(regex, e), file=sys.stderr)
        sys.exit(1)


def cmd_dfa(args):
    """Constructs Rabin-Scott Powerset DFA."""
    regex = getattr(args, 'regex_flag', None) or args.regex
    if not regex:
        print("[-] Error: Argument 'regex' is required", file=sys.stderr)
        sys.exit(1)
    print(f"\n[+] Synthesizing Rabin-Scott Powerset DFA for: '{regex}'")
    try:
        t0 = time.perf_counter()
        dfa = compile_to_dfa(regex)
        dt = (time.perf_counter() - t0) * 1000.0

        m = dfa.get_metrics()
        print(f"[*] Powerset DFA synthesized in {dt:.3f} ms")
        print(f"    - States |Q_D|:       {m['state_count']}")
        print(f"    - Transitions |δ_D|:  {m['transition_count']}")
        print(f"    - Start State:        {m['start_state']}")
        print(f"    - Accept States:      {m['accept_states']}")
        print(f"    - Alphabet:           {dfa.alphabet}")

        print("\nDeterministic Jump-Table:")
        print(dfa.generate_transition_table())

    except Exception as e:
        print(f"[-] DFA Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_minimize(args):
    """Executes Hopcroft's O(|Σ| n log n) DFA minimization."""
    regex = getattr(args, 'regex_flag', None) or args.regex
    if not regex:
        print("[-] Error: Argument 'regex' is required", file=sys.stderr)
        sys.exit(1)
    print(f"\n[+] Synthesizing Hopcroft Minimal DFA for: '{regex}'")
    try:
        t0 = time.perf_counter()
        powerset_dfa = compile_to_dfa(regex)
        min_dfa = powerset_dfa.minimize()
        dt = (time.perf_counter() - t0) * 1000.0

        p_states = len(powerset_dfa.states)
        m_states = len(min_dfa.states)
        reduc = round((1.0 - m_states / max(p_states, 1)) * 100.0, 1)

        print(f"[*] Hopcroft Minimization completed in {dt:.3f} ms")
        print(f"    - Powerset DFA States:   {p_states}")
        print(f"    - Canonical Min States:  {m_states}")
        print(f"    - State Reduction Ratio: {reduc}%")
        print(f"    - Start State:           D{min_dfa.start_state_id}")
        print(f"    - Accept States:         {[f'D{s.id}' for s in min_dfa.states.values() if s.is_accept]}")

        print("\nCanonical Minimal Transition Table:")
        print(min_dfa.generate_transition_table())

    except Exception as e:
        print(f"[-] Minimization Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_match(args):
    """Matches text across all 3 automata engines and verifies parity."""
    regex = getattr(args, 'regex_flag', None) or args.regex
    text = getattr(args, 'text_flag', None) or args.text
    if not regex or text is None:
        print("[-] Error: Arguments 'regex' and 'text' are required (e.g. finix match 'a*' 'aaa' or finix match --regex 'a*' --text 'aaa')", file=sys.stderr)
        sys.exit(1)
    print(f"\n[+] Pattern Matching Verification")
    print(f"    Pattern: '{regex}'")
    print(f"    Payload: '{text}' (Length: {len(text)})\n")

    try:
        nfa = compile_regex(regex)
        powerset_dfa = compile_to_dfa(regex)
        min_dfa = powerset_dfa.minimize()

        # 1. NFA Simulation
        t0 = time.perf_counter()
        nfa_res = NFASimulator(nfa).simulate(text)
        nfa_time = (time.perf_counter() - t0) * 1000.0

        # 2. Powerset DFA Simulation
        t0 = time.perf_counter()
        dfa_res = powerset_dfa.simulate(text)
        dfa_time = (time.perf_counter() - t0) * 1000.0

        # 3. Minimal DFA Jump Match
        t0 = time.perf_counter()
        min_verdict = min_dfa.match(text)
        min_time = (time.perf_counter() - t0) * 1000.0

        # Parity Check
        parity = (nfa_res.is_accepted == dfa_res.is_accepted == min_verdict)
        verdict_str = "ACCEPTED" if min_verdict else "REJECTED"

        print(f"{'Engine':<24} | {'Verdict':<12} | {'Latency':<14} | {'Complexity'}")
        print("-" * 72)
        print(f"{'Thompson ε-NFA':<24} | {('ACCEPTED' if nfa_res.is_accepted else 'REJECTED'):<12} | {nfa_time:.4f} ms    | O(|w|·|Q_N|²)")
        print(f"{'Powerset DFA':<24} | {('ACCEPTED' if dfa_res.is_accepted else 'REJECTED'):<12} | {dfa_time:.4f} ms    | O(|w|) 1-step")
        print(f"{'Hopcroft Minimal DFA':<24} | {verdict_str:<12} | {min_time:.4f} ms    | O(|w|) flat array")
        print("-" * 72)
        print(f"[*] Differential Parity Verified: {'PASS' if parity else 'FAIL'}")

        if args.trace:
            print("\nMinimal DFA Execution Trace:")
            min_trace = min_dfa.simulate(text)
            for step in min_trace.trace:
                tgt = f"D{step.to_state}" if step.to_state is not None else "TRAP"
                acc = " [ACCEPT]" if step.is_accept else ""
                print(f"  Step {step.step_idx}: '{step.char}'  D{step.from_state} -> {tgt}{acc}")

    except Exception as e:
        print(f"[-] Matching Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_equivalent(args):
    """Proves regular expression language equivalence via Myhill-Nerode isomorphism."""
    r1 = getattr(args, 'regex1_flag', None) or args.regex1
    r2 = getattr(args, 'regex2_flag', None) or args.regex2
    if not r1 or not r2:
        print("[-] Error: Arguments 'regex1' and 'regex2' are required", file=sys.stderr)
        sys.exit(1)
    print(f"\n[+] Formal Language Equivalence Theorem Prover")
    print(f"    L(r1) = L('{r1}')")
    print(f"    L(r2) = L('{r2}')\n")

    try:
        is_eq, explanation = are_equivalent_regexes(r1, r2)
        if is_eq:
            print("[*] VERDICT: EQUIVALENT (L(r1) ≡ L(r2))")
        else:
            print("[*] VERDICT: NOT EQUIVALENT (L(r1) ≢ L(r2))")
        print(f"\nMathematical Proof Summary:\n{explanation}")

    except Exception as e:
        print(f"[-] Equivalence Prover Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_benchmark(args):
    """Runs empirical ReDoS benchmark suite and exports SVG chart."""
    tax_id = args.taxonomy
    print(f"\n[+] Executing ReDoS Immunity Benchmark Suite")
    print(f"    Taxonomy: {tax_id}")

    suite = ReDoSBenchmarkSuite(timeout_sec=args.timeout)
    results = suite.run_benchmark(taxonomy_id=tax_id)

    print("\n" + results["ascii_table"])

    out_svg = args.out or "benchmark_chart.svg"
    with open(out_svg, "w", encoding="utf-8") as f:
        f.write(results["svg_chart"])
    print(f"\n[*] Exported publication-grade SVG chart to: {out_svg}")


def cmd_scan(args):
    """Executes high-throughput SIEM log or payload scanner."""
    scanner = SIEMLogScanner(rules_json_path=args.rules)
    print(f"\n[+] FINIX SIEM Security Scanner Loaded ({len(scanner.rules)} Active Signatures)")

    if args.payload:
        print(f"[*] Scanning Target Payload: '{args.payload}'")
        matches = scanner.master_dfa.scan_target(args.payload)
        if matches:
            print(f"[!] THREAT DETECTED: {len(matches)} Rule(s) Triggered!")
            for r in matches:
                print(f"    - [{r.threat_level}] {r.id}: {r.name} ({r.category})")
        else:
            print("[*] CLEAN: No malicious patterns detected.")

    elif args.log:
        print(f"[*] Scanning Log File: {args.log}")
        if not os.path.exists(args.log):
            print(f"[-] File not found: {args.log}", file=sys.stderr)
            sys.exit(1)

        with open(args.log, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        report = scanner.scan_lines(lines)
        print(f"\n=== Log Scan Summary Report ===")
        print(f"  Total Lines Scanned:    {report['total_lines_scanned']}")
        print(f"  Incidents Flagged:      {report['incidents_detected']}")
        print(f"  Clean Requests:         {report['clean_requests']}")
        print(f"  Processing Time:        {report['elapsed_ms']} ms")
        print(f"  Throughput:             {report['throughput_lines_per_sec']:,} lines/sec")
        print("\nThreat Level Breakdown:")
        for lvl, cnt in report["threat_breakdown"].items():
            print(f"    {lvl:<10}: {cnt}")

        if report["incidents"]:
            print("\nIncident Details (Sample):")
            for inc in report["incidents"][:10]:
                rules_str = ", ".join(r["id"] for r in inc["rules"])
                print(f"  Line {inc['line_number']} [{inc['highest_threat']}] {inc['ip']} - {inc['uri']} ({rules_str})")


def cmd_serve(args):
    """Launches server.py web server."""
    port = args.port or 8000
    print(f"\n[+] Starting FINIX Automata Server on http://localhost:{port}")
    import subprocess
    cmd = [sys.executable, "server.py", str(port)]
    subprocess.run(cmd)


def main():
    parser = argparse.ArgumentParser(
        prog="finix",
        description="FINIX: Linear-Time Automata Engine & ReDoS Mitigation Platform"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # compile
    p_comp = subparsers.add_parser("compile", help="Compile regex to Thompson ε-NFA")
    p_comp.add_argument("regex", nargs="?", default=None, help="Regular expression string")
    p_comp.add_argument("--regex", dest="regex_flag", default=None, help="Regular expression string")
    p_comp.add_argument("--table", action="store_true", help="Print full transition table")
    p_comp.set_defaults(func=cmd_compile)

    # dfa
    p_dfa = subparsers.add_parser("dfa", help="Construct Rabin-Scott Powerset DFA")
    p_dfa.add_argument("regex", nargs="?", default=None, help="Regular expression string")
    p_dfa.add_argument("--regex", dest="regex_flag", default=None, help="Regular expression string")
    p_dfa.set_defaults(func=cmd_dfa)

    # minimize
    p_min = subparsers.add_parser("minimize", help="Synthesize Hopcroft Canonical Minimal DFA")
    p_min.add_argument("regex", nargs="?", default=None, help="Regular expression string")
    p_min.add_argument("--regex", dest="regex_flag", default=None, help="Regular expression string")
    p_min.set_defaults(func=cmd_minimize)

    # match
    p_match = subparsers.add_parser("match", help="Match text across NFA, Powerset DFA, and Min-DFA")
    p_match.add_argument("regex", nargs="?", default=None, help="Regular expression string")
    p_match.add_argument("text", nargs="?", default=None, help="Input string to evaluate")
    p_match.add_argument("--regex", dest="regex_flag", default=None, help="Regular expression string")
    p_match.add_argument("--text", dest="text_flag", default=None, help="Input string to evaluate")
    p_match.add_argument("--trace", action="store_true", help="Display step execution trace")
    p_match.set_defaults(func=cmd_match)

    # equivalent
    p_eq = subparsers.add_parser("equivalent", help="Prove language equivalence L(r1) ≡ L(r2)")
    p_eq.add_argument("regex1", nargs="?", default=None, help="First regular expression")
    p_eq.add_argument("regex2", nargs="?", default=None, help="Second regular expression")
    p_eq.add_argument("--regex1", dest="regex1_flag", default=None, help="First regular expression")
    p_eq.add_argument("--regex2", dest="regex2_flag", default=None, help="Second regular expression")
    p_eq.set_defaults(func=cmd_equivalent)

    # benchmark
    p_bench = subparsers.add_parser("benchmark", help="Run empirical ReDoS benchmark")
    p_bench.add_argument("--taxonomy", default="TAXONOMY_1", choices=[t["id"] for t in BENCHMARK_TAXONOMIES])
    p_bench.add_argument("--timeout", type=float, default=1.5, help="Python re timeout in seconds")
    p_bench.add_argument("--out", help="Output path for SVG chart")
    p_bench.set_defaults(func=cmd_benchmark)

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan logs or payloads for security signatures")
    p_scan.add_argument("--payload", help="Single payload string to inspect")
    p_scan.add_argument("--log", help="Path to web server access log file")
    p_scan.add_argument("--rules", help="Custom JSON signatures file")
    p_scan.set_defaults(func=cmd_scan)

    # serve
    p_serve = subparsers.add_parser("serve", help="Launch interactive web GUI server")
    p_serve.add_argument("--port", type=int, default=8000, help="HTTP port")
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
