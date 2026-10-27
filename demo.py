"""
demo.py: Interactive Terminal Showcase and Automated Review-1 Slide Screenshot Generator.
Synthesizes all 5 modules from first principles:
  1. Lexer, Explicit Concat (·), and AST Parser
  2. Thompson's Inductive Construction (ε-NFA)
  3. Formal TOC State Transition Table
  4. Step-by-Step Simulation Trace
  5. Applied Security Signature Threat Scanner
"""

import sys
import os

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
from regex_nfa.simulator import NFASimulator
from regex_nfa.visualizer import Visualizer
from regex_nfa.security import SecurityScanner


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
    print("         FINIX Remastered: First-Principles Regular Expression Engine")
    print("               Theory of Computation — Review 1 Prototype")
    print("=" * 78 + f"{Color.END}")


def run_case(case_num: int, title: str, regex: str, test_cases: list):
    print(f"\n{Color.BOLD}{Color.HEADER}==============================================================================")
    print(f" SCREENSHOT CASE {case_num}: {title.upper()}")
    print(f"=============================================================================={Color.END}")
    print(f"{Color.BOLD}Input Regular Expression :{Color.END} {Color.CYAN}{regex}{Color.END}")

    # 1. Lexer & Concat Form
    raw_tokens = tokenize(regex)
    concat_tokens = insert_explicit_concat(raw_tokens)
    print(f"{Color.BOLD}Explicit Concat Form (·) :{Color.END} {' '.join(t.value for t in concat_tokens)}")

    # 2. Postfix & AST
    postfix_tokens = parse_regex(regex)
    print(f"{Color.BOLD}Postfix Notation (RPN)   :{Color.END} {format_postfix(postfix_tokens)}")
    ast = build_ast(postfix_tokens)
    ast_str = ast.to_string() if ast else "empty()"
    print(f"{Color.BOLD}Abstract Syntax Tree     :{Color.END} {Color.YELLOW}{ast_str}{Color.END}")

    # 3. Compile to NFA
    nfa = compile_regex(regex)
    metrics = nfa.get_metrics()
    print(f"{Color.BOLD}Constructed ε-NFA Metrics:{Color.END} {metrics['state_count']} states, {metrics['transition_count']} transitions ({metrics['epsilon_transition_count']} ε-moves)")

    # 4. Formal Transition Table
    print(f"\n{Color.BOLD}[Formal State Transition Table (δ)]{Color.END}")
    print(Visualizer.generate_transition_table(nfa))

    # 5. Simulation Test Suite
    simulator = NFASimulator(nfa)
    print(f"\n{Color.BOLD}[Simulation Test Suite]{Color.END}")
    for string, expected in test_cases:
        res = simulator.simulate(string)
        verdict = f"{Color.GREEN}ACCEPTED{Color.END}" if res.is_accepted else f"{Color.RED}REJECTED{Color.END}"
        expected_str = "ACCEPT" if expected else "REJECT"
        status = f"{Color.GREEN}PASS{Color.END}" if res.is_accepted == expected else f"{Color.RED}FAIL{Color.END}"
        display_str = f"'{string}'" if string != "" else "ε (empty string)"
        print(f"  • Input: {display_str:<26} -> Result: {verdict:<18} (Expected: {expected_str:<6} | Status: {status})")

    # 6. Detailed Step Trace
    if test_cases:
        sample_str = test_cases[0][0]
        sample_res = simulator.simulate(sample_str)
        print(f"\n{Color.BOLD}[Detailed Execution Trace for Input '{sample_str}']{Color.END}")
        print(Visualizer.format_simulation_trace(sample_res))

    # 7. Export Academic SVG Diagram (FINIX-1 Textbook Aesthetic)
    svg_content = Visualizer.generate_layered_svg(nfa)
    svg_filename = f"case{case_num}_nfa.svg"
    with open(svg_filename, "w", encoding="utf-8") as f:
        f.write(svg_content)
    with open("last_nfa.svg", "w", encoding="utf-8") as f:
        f.write(svg_content)
    print(f"\n{Color.CYAN}  [Generated publication-grade SVG: '{svg_filename}' & 'last_nfa.svg']{Color.END}")


def run_automated_showcase():
    banner()

    # Case 1: Basic Regex
    run_case(
        case_num=1,
        title="Basic Kleene Star & Concatenation (Accepted & Rejected Cases)",
        regex="a*b",
        test_cases=[
            ("aaab", True),
            ("b", True),
            ("ab", True),
            ("aaba", False),
            ("aaa", False),
            ("ba", False)
        ]
    )

    # Case 2: Union
    run_case(
        case_num=2,
        title="Union / Alternation Operator (|)",
        regex="a|b",
        test_cases=[
            ("a", True),
            ("b", True),
            ("c", False),
            ("ab", False),
            ("", False)
        ]
    )

    # Case 3: Textbook Expression
    run_case(
        case_num=3,
        title="Complex Textbook Expression: (a|b)*abb",
        regex="(a|b)*abb",
        test_cases=[
            ("abb", True),
            ("aabb", True),
            ("ababb", True),
            ("babb", True),
            ("ab", False),
            ("abba", False),
            ("", False)
        ]
    )

    # Case 4: Security Signature
    print(f"\n{Color.BOLD}{Color.HEADER}==============================================================================")
    print(f" SCREENSHOT CASE 4: SECURITY PATTERN MATCHING APPLICATION")
    print(f"=============================================================================={Color.END}")

    scanner = SecurityScanner()
    test_urls = [
        "https://example.com/file.exe",
        "http://malware-distribution.org/trojan.exe",
        "https://example.com/index.html",
        "http://test.com/document.pdf",
        "https://bank.com/admin/login",
        "https://company.org/update.sh",
        "admin' or '1'='1"
    ]

    print(f"{Color.BOLD}Registered Security Signatures:{Color.END}")
    for idx, rule in enumerate(scanner.rules, 1):
        print(f"  [{idx}] {rule.name:<40} | Level: {rule.threat_level:<8} | Pattern: {rule.pattern}")

    print(f"\n{Color.BOLD}[Live Security Traffic Scanner Feed]{Color.END}")
    print("-" * 78)
    for url in test_urls:
        report = scanner.scan(url)
        if report.is_flagged:
            rules_hit = ", ".join(f"[{m['rule'].id}] {m['rule'].name}" for m in report.matches)
            threat = report.highest_threat
            color = Color.RED if threat in ["CRITICAL", "HIGH"] else Color.YELLOW
            print(f" {color}[ALERT - {threat}]{Color.END} {url}")
            print(f"   └── Matched Signature(s): {Color.CYAN}{rules_hit}{Color.END}")
        else:
            print(f" {Color.GREEN}[CLEAN / BENIGN]{Color.END} {url}")
    print("-" * 78)


def interactive_mode():
    banner()
    print(f"{Color.CYAN}Interactive First-Principles Regex Simulator & Visualizer{Color.END}")
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
            print(f"  {Color.BOLD}Postfix (RPN):{Color.END} {format_postfix(postfix)}")

            ast = build_ast(postfix)
            if ast:
                print(f"  {Color.BOLD}AST Structure:{Color.END} {ast.to_string()}")

            nfa = compile_regex(regex)
            metrics = nfa.get_metrics()
            print(f"  {Color.BOLD}NFA Metrics  :{Color.END} {metrics['state_count']} states, {metrics['transition_count']} transitions ({metrics['epsilon_transition_count']} ε-moves)")

            print(f"\n{Color.BOLD}Formal State Transition Table (δ):{Color.END}")
            print(Visualizer.generate_transition_table(nfa))

            # DOT & SVG export
            dot_filename = "last_nfa.dot"
            with open(dot_filename, "w", encoding="utf-8") as f:
                f.write(Visualizer.export_graphviz_dot(nfa, title=f"NFA for /{regex}/"))
            svg_filename = "last_nfa.svg"
            with open(svg_filename, "w", encoding="utf-8") as f:
                f.write(Visualizer.generate_layered_svg(nfa))
            print(f"\n  [Diagrams saved: '{dot_filename}' (Graphviz) & '{svg_filename}' (Layered SVG)]")

            simulator = NFASimulator(nfa)
            print(f"\n{Color.CYAN}Enter test strings (type 'done' to change regex):{Color.END}")
            while True:
                test_str = input("  Test String: ")
                if test_str.lower() in {'done', 'back'}:
                    break
                result = simulator.simulate(test_str)
                if result.is_accepted:
                    print(f"  -> {Color.GREEN}{Color.BOLD}ACCEPTED{Color.END} ✓ ({result.elapsed_ms:.3f} ms)")
                else:
                    print(f"  -> {Color.RED}{Color.BOLD}REJECTED{Color.END} ✗ ({result.elapsed_ms:.3f} ms)")

                show_trace = input("  Show step-by-step trace? (y/n): ").strip().lower()
                if show_trace == 'y':
                    print("\n" + Visualizer.format_simulation_trace(result) + "\n")

            print("\n" + "=" * 78 + "\n")

        except Exception as e:
            print(f"{Color.RED}Error: {e}{Color.END}\n")


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == "--interactive":
        interactive_mode()
    else:
        run_automated_showcase()
        print(f"\n{Color.CYAN}Tip: Run `python demo.py --interactive` for live interactive prompt!{Color.END}\n")
