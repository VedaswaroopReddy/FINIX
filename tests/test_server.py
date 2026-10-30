"""
test_server.py: Automated Regression Tests for FINIX REST API Endpoints.
Verifies all 7 HTTP/JSON endpoints exposed by FinixHttpHandler.
"""

import json
import urllib.request
import threading
import time
import socketserver
import pytest
from server import FinixHttpHandler


class ReusableServer(socketserver.TCPServer):
    allow_reuse_address = True


@pytest.fixture(scope="module")
def api_server():
    server = ReusableServer(('127.0.0.1', 8897), FinixHttpHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)
    base_url = "http://127.0.0.1:8897"
    yield base_url
    server.shutdown()
    server.server_close()


def _post_json(base_url, endpoint, data):
    req = urllib.request.Request(
        f"{base_url}{endpoint}",
        data=json.dumps(data).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode('utf-8'))


def _get_json(base_url, endpoint):
    req = urllib.request.Request(f"{base_url}{endpoint}")
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode('utf-8'))


class TestServerEndpoints:
    def test_api_compile(self, api_server):
        status, res = _post_json(api_server, '/api/compile', {'regex': '(a|b)*abb'})
        assert status == 200
        assert res['metrics']['state_count'] == 14
        assert len(res['dfa']['nodes']) == 5
        assert len(res['minimal_dfa']['nodes']) == 4

    def test_api_simulate(self, api_server):
        status, res = _post_json(api_server, '/api/simulate', {'regex': '(a|b)*abb', 'input_string': 'ababb'})
        assert status == 200
        assert res['is_accepted'] is True
        assert len(res['trace']) == 5
        assert res['dfa_simulation']['is_accepted'] is True
        assert res['min_dfa_simulation']['is_accepted'] is True

    def test_api_equivalent(self, api_server):
        status, res = _post_json(api_server, '/api/equivalent', {'regex1': 'a+', 'regex2': 'a*'})
        assert status == 200
        assert res['is_equivalent'] is False
        assert "STRICT SUBSET" in res['explanation']

    def test_api_benchmark(self, api_server):
        status, res = _post_json(api_server, '/api/benchmark', {'taxonomy': 'TAXONOMY_1', 'lengths': [6, 10]})
        assert status == 200
        assert len(res['data_points']) == 2

    def test_api_siem_rules(self, api_server):
        status, res = _get_json(api_server, '/api/siem/rules')
        assert status == 200
        assert len(res['rules']) >= 10

    def test_api_siem_scan_payload(self, api_server):
        status, res = _post_json(api_server, '/api/siem/scan', {'payload': "GET /login?user=' or 1=1 HTTP/1.1"})
        assert status == 200
        assert res['is_flagged'] is True
        assert res['highest_threat'] == "CRITICAL"

    def test_api_siem_scan_logs(self, api_server):
        status, res = _post_json(api_server, '/api/siem/scan', {'log_lines': [
            '192.168.1.1 - - [20/Oct/2026:12:10:00 +0000] "GET /index.html HTTP/1.1" 200 5000',
            '192.168.1.2 - - [20/Oct/2026:12:10:01 +0000] "GET /login?user=\' or 1=1 HTTP/1.1" 401 230'
        ]})
        assert status == 200
        assert res['total_lines_scanned'] == 2
        assert res['incidents_detected'] == 1
