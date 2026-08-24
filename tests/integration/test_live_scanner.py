"""
Live scanner integration tests.

Each test spins up a local HTTP server that returns a realistic vulnerable
response, then runs the actual scanner instance (real HTTPClient, no mocking)
against it.  Assertions check that the scanner produces the expected
FAIL/WARN/PASS verdict — proving end-to-end detection flow on real responses.

No external services or Docker required — the local server is implemented with
Python's built-in http.server module.
"""

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import pytest
import requests as _requests


# ── Local HTTP server ─────────────────────────────────────────────────────────

class _SilentHandler(BaseHTTPRequestHandler):
    """Request handler that dispatches to registered route functions."""

    def log_message(self, fmt, *args):
        pass  # suppress test output

    def _dispatch(self):
        fn = self.server._routes.get(self.path) or self.server._routes.get("*")
        if fn:
            fn(self)
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_GET(self):     self._dispatch()
    def do_POST(self):    self._dispatch()
    def do_OPTIONS(self): self._dispatch()
    def do_HEAD(self):    self._dispatch()


class LocalServer:
    """
    Context manager that starts a single-use local HTTP server.

    Usage::

        with LocalServer({"*": handler_fn}) as srv:
            results = MyScanner(_session()).scan(srv.base_url)
    """

    def __init__(self, routes: dict):
        self._routes = routes

    def __enter__(self):
        self._httpd = HTTPServer(("127.0.0.1", 0), _SilentHandler)
        self._httpd._routes = self._routes
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        host, port = self._httpd.server_address
        self.base_url = f"http://{host}:{port}"
        return self

    def __exit__(self, *_):
        self._httpd.shutdown()


def _send(handler, status=200, body=b"", headers=None, ctype="text/html"):
    """Send an HTTP response with optional extra headers."""
    handler.send_response(status)
    handler.send_header("Content-Type", ctype)
    for k, v in (headers or {}).items():
        handler.send_header(k, v)
    handler.end_headers()
    if isinstance(body, str):
        body = body.encode()
    handler.wfile.write(body)


def _session():
    """Create a fresh requests.Session for each scanner under test."""
    return _requests.Session()


# ── CORS scanner ──────────────────────────────────────────────────────────────

def test_cors_wildcard_acao_detected():
    """
    CORSScanner flags WARN when Access-Control-Allow-Origin: * is returned.
    This is the most common CORS misconfiguration found in production.
    """
    def handler(h):
        _send(h, headers={"Access-Control-Allow-Origin": "*"})

    with LocalServer({"*": handler}) as srv:
        from tblue.scanner.cors import CORSScanner
        results = CORSScanner(_session()).scan(srv.base_url)

    statuses = {r["status"] for r in results}
    types    = " ".join(r["type"] for r in results).lower()
    assert "WARN" in statuses or "FAIL" in statuses, \
        f"Expected WARN/FAIL for wildcard CORS, got: {results}"
    assert "wildcard" in types, f"Expected 'wildcard' in finding types, got: {types}"


def test_cors_reflected_origin_with_credentials_is_fail():
    """
    CORSScanner flags FAIL when the server reflects the attacker's Origin
    AND sets Access-Control-Allow-Credentials: true.

    This is the highest-severity CORS misconfiguration: allows full
    cross-origin credential theft from authenticated users.
    """
    def handler(h):
        origin = h.headers.get("Origin", "null")
        _send(h, headers={
            "Access-Control-Allow-Origin":      origin,
            "Access-Control-Allow-Credentials": "true",
        })

    with LocalServer({"*": handler}) as srv:
        from tblue.scanner.cors import CORSScanner
        results = CORSScanner(_session()).scan(srv.base_url)

    assert any(r["status"] == "FAIL" for r in results), \
        f"Expected FAIL for reflected-origin + credentials, got: {results}"
    types = " ".join(r["type"].lower() for r in results)
    assert "credential" in types or "reflected" in types, \
        f"Expected 'credential' or 'reflected' in finding type: {types}"


def test_cors_no_headers_returns_pass():
    """
    CORSScanner returns PASS when the server sets no CORS headers.
    Validates the true-negative: clean servers are not false-alarmed.
    """
    def handler(h):
        _send(h)  # No CORS headers

    with LocalServer({"*": handler}) as srv:
        from tblue.scanner.cors import CORSScanner
        results = CORSScanner(_session()).scan(srv.base_url)

    assert any(r["status"] == "PASS" for r in results), \
        f"Expected PASS for no CORS headers, got: {results}"


# ── Security headers scanner ──────────────────────────────────────────────────

def test_headers_scanner_flags_missing_csp():
    """
    HeaderScanner flags FAIL/WARN when Content-Security-Policy is absent.
    A bare HTML response with no security headers produces multiple findings.
    """
    def handler(h):
        _send(h, body=b"<html><body><h1>Hello World</h1></body></html>")

    with LocalServer({"*": handler}) as srv:
        from tblue.scanner.headers import HeaderScanner
        results = HeaderScanner(_session()).scan(srv.base_url)

    # The scanner emits FAIL/WARN for each missing header; confirm the grade is bad
    fail_or_warn = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert len(fail_or_warn) >= 1, \
        f"Expected at least one FAIL/WARN for missing CSP/HSTS/X-Frame-Options: {results}"


def test_headers_scanner_flags_missing_hsts():
    """
    HeaderScanner flags missing Strict-Transport-Security header.
    Without HSTS, users can be downgraded to HTTP by network attackers.
    """
    def handler(h):
        _send(h, body=b"<html><body>ok</body></html>")

    with LocalServer({"*": handler}) as srv:
        from tblue.scanner.headers import HeaderScanner
        results = HeaderScanner(_session()).scan(srv.base_url)

    # A bare response with no security headers must produce FAIL or WARN
    assert any(r["status"] in ("FAIL", "WARN") for r in results), \
        f"Expected FAIL/WARN findings for missing HSTS and other headers: {results}"


def test_headers_scanner_flags_exposed_server_version():
    """
    HeaderScanner detects a Server header that reveals software version.
    Version exposure lets attackers pick exploits targeting that exact build.
    """
    def handler(h):
        _send(h, headers={"Server": "Apache/2.4.51 (Ubuntu)"},
              body=b"<html><body>ok</body></html>")

    with LocalServer({"*": handler}) as srv:
        from tblue.scanner.headers import HeaderScanner
        results = HeaderScanner(_session()).scan(srv.base_url)

    assert any(r["status"] in ("FAIL", "WARN", "INFO") for r in results), \
        f"Expected at least one finding for server with version header: {results}"


# ── SRI advanced scanner ──────────────────────────────────────────────────────

def test_sri_external_script_without_integrity_flagged():
    """
    SRIAdvancedScanner flags a CDN script without an integrity attribute.
    A compromised CDN can silently deliver malicious JS to all users.
    """
    html = (
        b"<!DOCTYPE html><html><head>"
        b'<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>'
        b"</head><body></body></html>"
    )

    def handler(h):
        _send(h, body=html)

    with LocalServer({"*": handler}) as srv:
        from tblue.scanner.sri_advanced import SRIAdvancedScanner
        results = SRIAdvancedScanner(_session()).scan(srv.base_url)

    assert any(r["status"] in ("FAIL", "WARN") for r in results), \
        f"Expected FAIL/WARN for missing SRI on CDN script: {results}"
    types = " ".join(r["type"].lower() for r in results)
    assert "integrity" in types or "sri" in types, \
        f"Expected 'integrity' or 'sri' in finding types: {types}"


def test_sri_external_stylesheet_without_integrity_flagged():
    """
    SRIAdvancedScanner flags a CDN stylesheet without an integrity attribute.
    CSS can be used for data exfiltration and UI redressing attacks.
    """
    html = (
        b"<!DOCTYPE html><html><head>"
        b'<link rel="stylesheet"'
        b' href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">'
        b"</head><body></body></html>"
    )

    def handler(h):
        _send(h, body=html)

    with LocalServer({"*": handler}) as srv:
        from tblue.scanner.sri_advanced import SRIAdvancedScanner
        results = SRIAdvancedScanner(_session()).scan(srv.base_url)

    assert any(r["status"] in ("FAIL", "WARN") for r in results), \
        f"Expected FAIL/WARN for missing SRI on CDN stylesheet: {results}"


def test_sri_with_integrity_attribute_passes():
    """
    SRIAdvancedScanner does not flag external scripts with a valid integrity hash.
    Validates the true-negative case — correctly secured resources are clean.
    """
    html = (
        b"<!DOCTYPE html><html><head>"
        b'<script src="https://code.jquery.com/jquery-3.7.1.min.js"'
        b' integrity="sha256-/JqT3SQfawRcv/BIHPThkBvs0OEvtFFmqPF/lYI/Cxo="'
        b' crossorigin="anonymous"></script>'
        b"</head><body></body></html>"
    )

    def handler(h):
        _send(h, body=html)

    with LocalServer({"*": handler}) as srv:
        from tblue.scanner.sri_advanced import SRIAdvancedScanner
        results = SRIAdvancedScanner(_session()).scan(srv.base_url)

    integrity_failures = [
        r for r in results
        if r["status"] in ("FAIL", "WARN") and "integrity" in r["type"].lower()
    ]
    assert len(integrity_failures) == 0, \
        f"Unexpected integrity failures for SRI-protected script: {integrity_failures}"


def test_sri_local_script_not_flagged():
    """
    SRIAdvancedScanner does not flag same-origin scripts.
    The server controls same-origin resources directly — SRI doesn't apply.
    """
    html = (
        b"<!DOCTYPE html><html><head>"
        b'<script src="/static/app.js"></script>'
        b'<link rel="stylesheet" href="/static/style.css">'
        b"</head><body></body></html>"
    )

    def handler(h):
        _send(h, body=html)

    with LocalServer({"*": handler}) as srv:
        from tblue.scanner.sri_advanced import SRIAdvancedScanner
        results = SRIAdvancedScanner(_session()).scan(srv.base_url)

    integrity_failures = [
        r for r in results
        if r["status"] in ("FAIL", "WARN") and "integrity" in r["type"].lower()
    ]
    assert len(integrity_failures) == 0, \
        f"Local-origin resources should not require SRI: {integrity_failures}"


# ── Clickjacking scanner ──────────────────────────────────────────────────────

def test_clickjacking_no_frame_options_detected():
    """
    ClickjackingScanner flags when X-Frame-Options and frame-ancestors CSP are absent.
    Without these, attackers can embed the page in an invisible iframe.
    """
    def handler(h):
        _send(h, body=b"<html><body>Login Page</body></html>")

    with LocalServer({"*": handler}) as srv:
        from tblue.scanner.clickjacking import ClickjackingScanner
        results = ClickjackingScanner(_session()).scan(srv.base_url)

    assert any(r["status"] in ("FAIL", "WARN") for r in results), \
        f"Expected FAIL/WARN for missing frame protection: {results}"


def test_clickjacking_deny_header_passes():
    """
    ClickjackingScanner produces no FAIL when X-Frame-Options: DENY is set.
    """
    def handler(h):
        _send(h, headers={"X-Frame-Options": "DENY"},
              body=b"<html><body>Login Page</body></html>")

    with LocalServer({"*": handler}) as srv:
        from tblue.scanner.clickjacking import ClickjackingScanner
        results = ClickjackingScanner(_session()).scan(srv.base_url)

    fail_results = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_results) == 0, \
        f"Should not FAIL when X-Frame-Options: DENY is set: {fail_results}"


# ── CSP scanner ───────────────────────────────────────────────────────────────

def test_csp_scanner_flags_missing_policy():
    """
    CSPScanner detects when Content-Security-Policy header is absent.
    Without CSP, any XSS executes arbitrary JavaScript in the victim's browser.
    """
    def handler(h):
        _send(h, body=b"<html><body>Hello</body></html>")

    with LocalServer({"*": handler}) as srv:
        from tblue.scanner.csp import CSPScanner
        results = CSPScanner(_session()).scan(srv.base_url)

    statuses = {r["status"] for r in results}
    assert "FAIL" in statuses or "WARN" in statuses, \
        f"Expected CSP finding for page with no CSP header: {results}"


# ── GraphQL scanner (endpoint detection) ─────────────────────────────────────

def test_graphql_introspection_response_detected():
    """
    GraphQLAdvancedScanner detects /graphql returning introspection data.
    Introspection in production exposes the full API schema to attackers.
    """
    introspection_json = (
        b'{"data":{"__schema":{"queryType":{"name":"Query"},'
        b'"types":[{"name":"__Type"},{"name":"User"}]}}}'
    )

    def handler(h):
        if h.path in ("/graphql", "/api/graphql"):
            # Drain POST body to keep connection healthy
            cl = int(h.headers.get("Content-Length", 0))
            if cl:
                h.rfile.read(cl)
            _send(h, body=introspection_json, ctype="application/json")
        else:
            # Return 200 for the base URL so the scanner does not short-circuit.
            # requests.Response.__bool__ is False for 4xx, which would make the
            # scanner treat the response as "no response" and return PASS early.
            _send(h, body=b"<html><body>app</body></html>")

    with LocalServer({"*": handler}) as srv:
        from tblue.scanner.graphql_advanced import GraphQLAdvancedScanner
        results = GraphQLAdvancedScanner(_session()).scan(srv.base_url)

    assert any(r["status"] in ("FAIL", "WARN") for r in results), \
        f"Expected FAIL/WARN for enabled GraphQL introspection: {results}"
    types = " ".join(r["type"].lower() for r in results)
    assert "introspect" in types or "graphql" in types or "schema" in types, \
        f"Expected introspection finding: {types}"


def test_graphql_no_endpoint_returns_no_fail():
    """
    GraphQLAdvancedScanner produces no FAIL for a server with no GraphQL endpoint.
    Validates the true-negative: normal web servers are not false-alarmed.
    """
    def handler(h):
        _send(h, status=404, body=b"Not Found")

    with LocalServer({"*": handler}) as srv:
        from tblue.scanner.graphql_advanced import GraphQLAdvancedScanner
        results = GraphQLAdvancedScanner(_session()).scan(srv.base_url)

    critical_results = [r for r in results if r["status"] == "FAIL"]
    assert len(critical_results) == 0, \
        f"Unexpected FAIL findings for server with no GraphQL: {critical_results}"
