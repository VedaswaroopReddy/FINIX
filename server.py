"""
server.py: Production HTTP Server & REST API Platform for FINIX.
Provides zero-dependency REST endpoints and interactive web visualizer hosting.
"""

import http.server
import socket
import socketserver
import json
import urllib.parse
import sys
import os
import time
from typing import Dict, Any, List

# Ensure UTF-8 output
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except (AttributeError, ValueError, OSError) as _err:
        sys.stderr.write(f"Notice: stdout reconfigure unavailable: {_err}\n")

from regex_nfa.parser import parse_regex, format_postfix, build_ast, tokenize, insert_explicit_concat
from regex_nfa.thompson import compile_regex
from regex_nfa.simulator import NFASimulator
from regex_nfa.visualizer import Visualizer
from regex_nfa.nfa import EPSILON, WILDCARD
from regex_nfa.dfa import nfa_to_dfa
from regex_nfa.minimizer import are_equivalent_regexes
from regex_nfa.benchmarks import ReDoSBenchmarkSuite
from regex_nfa.scanner import SIEMLogScanner

PORT = 8000
DIRECTORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web')

siem_scanner = SIEMLogScanner()
benchmark_suite = ReDoSBenchmarkSuite(timeout_sec=1.5)


class FinixHttpHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, directory=None, **kwargs):
        if directory is None:
            directory = DIRECTORY
        super().__init__(*args, directory=directory, **kwargs)

    def end_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'SAMEORIGIN')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')

        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        try:
            req_json = json.loads(post_data) if post_data else {}
        except json.JSONDecodeError as decode_err:
            req_json = {"error": f"Invalid JSON payload: {decode_err}"}

        if path == '/api/compile':
            self.handle_compile(req_json)
        elif path == '/api/simulate':
            self.handle_simulate(req_json)
        elif path == '/api/equivalent':
            self.handle_equivalent(req_json)
        elif path == '/api/benchmark':
            self.handle_benchmark(req_json)
        elif path == '/api/siem/scan':
            self.handle_siem_scan(req_json)
        else:
            self.send_error(404, "Endpoint not found")

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path == '/api/siem/rules':
            self.handle_get_siem_rules()
        else:
            super().do_GET()

    def send_json_response(self, data: Dict[str, Any], status: int = 200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        allowed_origin = os.environ.get('FINIX_ALLOWED_ORIGIN', '*')
        origin = self.headers.get('Origin', '')
        if origin and ('localhost' in origin or '127.0.0.1' in origin):
            self.send_header('Access-Control-Allow-Origin', origin)
        else:
            self.send_header('Access-Control-Allow-Origin', allowed_origin)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def handle_compile(self, req: Dict[str, Any]):
        regex = req.get('regex', '')
        if not regex:
            self.send_json_response({"error": "Empty regular expression"}, status=400)
            return

        try:
            t_start = time.perf_counter()
            raw_tokens = tokenize(regex)
            concat_tokens = insert_explicit_concat(raw_tokens)
            postfix_tokens = parse_regex(regex)
            postfix_str = format_postfix(postfix_tokens)

            ast = build_ast(postfix_tokens)
            ast_str = ast.to_string() if ast else "empty()"

            nfa = compile_regex(regex)
            build_time_ms = (time.perf_counter() - t_start) * 1000.0
            states = sorted(list(nfa.get_all_states()), key=lambda s: s.id)
            metrics = nfa.get_metrics()

            # Columns for Transition Table: [ε] + sorted literals + sorted charsets + [Σ] (if wildcard present)
            literal_symbols = sorted(list(nfa.get_alphabet()))
            charsets = sorted([cs.display() for cs in nfa.get_charsets()])
            columns = [EPSILON] + literal_symbols + charsets
            if nfa.has_wildcard():
                columns.append(WILDCARD)

            table_rows = []
            for s in states:
                row = {
                    "state": f"q{s.id}",
                    "is_start": (s == nfa.start_state),
                    "is_accept": (s == nfa.accept_state or s.is_accept),
                    "transitions": {}
                }
                for col in columns:
                    targets = []
                    for sym, dests in s.transitions.items():
                        if sym.display() == col:
                            targets.extend([f"q{d.id}" for d in dests])
                    row["transitions"][col] = sorted(list(set(targets)))
                table_rows.append(row)

            # Build Node and Edge graphs for visualizer
            nodes = []
            for s in states:
                nodes.append({
                    "id": f"q{s.id}",
                    "label": f"q{s.id}",
                    "is_start": (s == nfa.start_state),
                    "is_accept": (s == nfa.accept_state or s.is_accept)
                })

            edges = []
            edge_map: Dict[tuple, List[str]] = {}
            flat_transitions = []
            for s in states:
                for sym, dests in s.transitions.items():
                    for d in dests:
                        key = (f"q{s.id}", f"q{d.id}")
                        if key not in edge_map:
                            edge_map[key] = []
                        edge_map[key].append(sym.display())
                        flat_transitions.append({
                            "from": f"q{s.id}",
                            "symbol": sym.display(),
                            "is_epsilon": (sym.display() == EPSILON),
                            "to": f"q{d.id}",
                            "to_is_accept": (d == nfa.accept_state or d.is_accept)
                        })

            for (src, tgt), syms in edge_map.items():
                edges.append({
                    "from": src,
                    "to": tgt,
                    "label": ", ".join(syms),
                    "is_epsilon": (EPSILON in syms)
                })

            dot_code = Visualizer.export_graphviz_dot(nfa, title=f"NFA for /{regex}/")
            svg_code = Visualizer.generate_layered_svg(nfa)

            # 1. Compile Powerset DFA (Rabin-Scott)
            dfa = nfa_to_dfa(nfa)
            dfa_data = dfa.to_dict()

            # 2. Compile Hopcroft Canonical Minimal DFA
            min_dfa = dfa.minimize()
            min_dfa_data = min_dfa.to_dict()

            self.send_json_response({
                "regex": regex,
                "explicit_form": " ".join(t.value for t in concat_tokens),
                "postfix": postfix_str,
                "ast": ast_str,
                "metrics": metrics,
                "columns": columns,
                "table": table_rows,
                "flat_transitions": flat_transitions,
                "alphabet": literal_symbols,
                "build_time_ms": round(build_time_ms, 3),
                "graph": {
                    "nodes": nodes,
                    "edges": edges
                },
                "dot": dot_code,
                "svg": svg_code,
                "dfa": dfa_data,
                "minimal_dfa": min_dfa_data
            })
        except Exception as e:
            self.send_json_response({"error": str(e)}, status=400)

    def handle_simulate(self, req: Dict[str, Any]):
        regex = req.get('regex', '')
        input_string = req.get('input_string', '')

        try:
            nfa = compile_regex(regex)
            simulator = NFASimulator(nfa)
            result = simulator.simulate(input_string)

            dfa = nfa_to_dfa(nfa)
            dfa_sim = dfa.simulate(input_string)

            min_dfa = dfa.minimize()
            min_dfa_sim = min_dfa.simulate(input_string)

            self.send_json_response({
                "regex": regex,
                "input_string": input_string,
                "is_accepted": result.is_accepted,
                "elapsed_ms": result.elapsed_ms,
                "initial_states": [f"q{s.id}" for s in result.initial_states],
                "final_states": [f"q{s.id}" for s in result.final_states],
                "trace": [t.to_dict() for t in result.trace],
                "dfa_simulation": dfa_sim.to_dict(),
                "min_dfa_simulation": min_dfa_sim.to_dict()
            })
        except Exception as e:
            self.send_json_response({"error": str(e)}, status=400)

    def handle_equivalent(self, req: Dict[str, Any]):
        r1 = req.get('regex1', '')
        r2 = req.get('regex2', '')
        if not r1 or not r2:
            self.send_json_response({"error": "Both regex1 and regex2 are required"}, status=400)
            return

        try:
            is_eq, msg = are_equivalent_regexes(r1, r2)
            self.send_json_response({
                "regex1": r1,
                "regex2": r2,
                "is_equivalent": is_eq,
                "explanation": msg
            })
        except Exception as e:
            self.send_json_response({"error": str(e)}, status=400)

    def handle_benchmark(self, req: Dict[str, Any]):
        taxonomy_id = req.get('taxonomy', 'TAXONOMY_1')
        lengths = req.get('lengths')
        try:
            res = benchmark_suite.run_benchmark(taxonomy_id=taxonomy_id, lengths=lengths)
            self.send_json_response(res)
        except Exception as e:
            self.send_json_response({"error": str(e)}, status=400)

    def handle_siem_scan(self, req: Dict[str, Any]):
        payload = req.get('payload')
        log_lines = req.get('log_lines')

        try:
            if payload:
                matches = siem_scanner.master_dfa.scan_target(payload)
                self.send_json_response({
                    "target": payload,
                    "is_flagged": len(matches) > 0,
                    "highest_threat": max([r.threat_level for r in matches], key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x, 0)) if matches else "SAFE",
                    "matches": [r.to_dict() for r in matches]
                })
            elif log_lines:
                report = siem_scanner.scan_lines(log_lines)
                self.send_json_response(report)
            else:
                self.send_json_response({"error": "Either 'payload' or 'log_lines' must be provided"}, status=400)
        except Exception as e:
            self.send_json_response({"error": str(e)}, status=400)

    def handle_get_siem_rules(self):
        self.send_json_response({
            "rules": [r.to_dict() for r in siem_scanner.rules]
        })


class DualStackThreadingServer(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        try:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except Exception:
            pass
        super().server_bind()


def run_server(port: int = None):
    p = port or (int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else int(os.environ.get('PORT', PORT)))
    os.makedirs(DIRECTORY, exist_ok=True)
    DualStackThreadingServer.allow_reuse_address = True
    try:
        httpd = DualStackThreadingServer(('::', p), FinixHttpHandler)
    except Exception:
        DualStackThreadingServer.address_family = socket.AF_INET
        httpd = DualStackThreadingServer(('', p), FinixHttpHandler)
    with httpd:
        print("=" * 76, flush=True)
        print(f"FINIX server running at: http://localhost:{p} and http://127.0.0.1:{p}", flush=True)
        print("=" * 76, flush=True)
        print("Interactive automata visualizer, step debugger, and REST API.", flush=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped.", flush=True)


if __name__ == '__main__':
    run_server()
