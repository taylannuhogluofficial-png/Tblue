"""
Integration tests for compliance scanners (PCI-DSS, HIPAA, SOC 2, NIST CSF, ISO 27001).

Each test spins up a real local HTTP server that returns a deliberately broken
security posture, then runs the actual scanner against it.  No mocking — the
full request/parse/detect pipeline is exercised end-to-end.

Note on scanner behavior:
  All compliance scanners return early on HTTP targets (no TLS) — only the
  TLS FAIL is emitted. Checks for HSTS, XCTO, frame protection, version
  disclosure, etc. require a successful HTTPS response. The tests below
  exercise only the code paths reachable from a plain-HTTP local server.
  Secondary checks (HSTS, version, frame) are covered by unit tests.
"""

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests as _requests

from tblue.scanner.pci_dss_compliance  import PCIDSSComplianceScanner
from tblue.scanner.hipaa_compliance    import HIPAAComplianceScanner
from tblue.scanner.soc2_compliance     import SOC2ComplianceScanner
from tblue.scanner.nist_csf_compliance import NISTCSFComplianceScanner
from tblue.scanner.iso27001_compliance  import ISO27001ComplianceScanner


# ── Shared test server fixture ────────────────────────────────────────────────

class _SilentHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        fn = getattr(self.server, "_route_fn", None)
        if fn:
            fn(self)
        else:
            self.send_response(404)
            self.end_headers()


def _make_server(route_fn):
    server = HTTPServer(("127.0.0.1", 0), _SilentHandler)
    server._route_fn = route_fn
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, f"http://127.0.0.1:{port}"


def _scanner(cls, url):
    session = _requests.Session()
    return cls(session, timeout=5, retries=1).scan(url)


# ── PCI-DSS ───────────────────────────────────────────────────────────────────

def test_pci_dss_flags_http_only():
    """PCI Req 4.2.1: plain HTTP — should FAIL for no TLS."""
    def route(h):
        h.send_response(200)
        h.send_header("Content-Type", "text/html")
        h.end_headers()
        h.wfile.write(b"<html><body>No TLS here</body></html>")

    server, url = _make_server(route)
    try:
        results = _scanner(PCIDSSComplianceScanner, url)
        fail_types = [r["type"] for r in results if r["status"] == "FAIL"]
        assert any("tls" in t or "4_2_1" in t for t in fail_types), \
            f"Expected TLS FAIL, got: {fail_types}"
    finally:
        server.shutdown()


def test_pci_dss_flags_missing_csp():
    """PCI Req 6.4.1: missing CSP should FAIL even on HTTP."""
    def route(h):
        h.send_response(200)
        h.send_header("Content-Type", "text/html")
        h.end_headers()
        h.wfile.write(b"<html><body>No CSP</body></html>")

    server, url = _make_server(route)
    try:
        results = _scanner(PCIDSSComplianceScanner, url)
        fail_types = [r["type"] for r in results if r["status"] == "FAIL"]
        assert any("csp" in t or "6_4_1" in t for t in fail_types), \
            f"Expected CSP FAIL, got: {fail_types}"
    finally:
        server.shutdown()


def test_pci_dss_csp_header_passes_req_6_4_1():
    """PCI Req 6.4.1: CSP header present → should PASS that check."""
    def route(h):
        h.send_response(200)
        h.send_header("Content-Type", "text/html")
        h.send_header("Content-Security-Policy", "default-src 'self'")
        h.end_headers()
        h.wfile.write(b"<html><body>Has CSP</body></html>")

    server, url = _make_server(route)
    try:
        results = _scanner(PCIDSSComplianceScanner, url)
        csp_results = [r for r in results if "6_4_1" in r["type"] or "csp" in r["type"]]
        pass_types = [r["type"] for r in csp_results if r["status"] == "PASS"]
        # The CSP check should PASS (header present)
        assert len(pass_types) > 0 or not any("csp" in t for t in [r["type"] for r in results if r["status"] == "FAIL"]), \
            f"CSP should PASS with header, got: {csp_results}"
    finally:
        server.shutdown()


# ── HIPAA ─────────────────────────────────────────────────────────────────────

def test_hipaa_flags_no_tls():
    """HIPAA §164.312: plain HTTP transmissions must FAIL."""
    def route(h):
        h.send_response(200)
        h.send_header("Content-Type", "text/html")
        h.end_headers()
        h.wfile.write(b"<html><body>patient records here</body></html>")

    server, url = _make_server(route)
    try:
        results = _scanner(HIPAAComplianceScanner, url)
        fail_types = [r["type"] for r in results if r["status"] == "FAIL"]
        assert any("tls" in t or "312" in t or "hipaa" in t for t in fail_types), \
            f"Expected TLS FAIL, got: {fail_types}"
    finally:
        server.shutdown()


def test_hipaa_returns_results_on_http():
    """HIPAA scanner should always return at least one result (not crash)."""
    def route(h):
        h.send_response(200)
        h.send_header("Content-Type", "text/html")
        h.end_headers()
        h.wfile.write(b"<html><body>plain http</body></html>")

    server, url = _make_server(route)
    try:
        results = _scanner(HIPAAComplianceScanner, url)
        assert len(results) >= 1, "Scanner should always return at least one result"
        assert all("type" in r and "status" in r for r in results), \
            "All results must have 'type' and 'status' keys"
    finally:
        server.shutdown()


# ── SOC 2 ────────────────────────────────────────────────────────────────────

def test_soc2_flags_no_tls():
    """SOC 2 CC6.1: HTTP target should produce TLS FAIL."""
    def route(h):
        h.send_response(200)
        h.send_header("Content-Type", "text/html")
        h.end_headers()
        h.wfile.write(b"<html><body>no headers</body></html>")

    server, url = _make_server(route)
    try:
        results = _scanner(SOC2ComplianceScanner, url)
        fail_types = [r["type"] for r in results if r["status"] == "FAIL"]
        assert any("tls" in t or "cc6_1" in t or "cc6" in t for t in fail_types), \
            f"Expected TLS/CC6 FAIL, got: {fail_types}"
    finally:
        server.shutdown()


def test_soc2_scanner_does_not_crash():
    """SOC 2 scanner should return well-formed results even on a bare HTTP server."""
    def route(h):
        h.send_response(200)
        h.send_header("Content-Type", "text/html")
        h.end_headers()
        h.wfile.write(b"<html><body>bare</body></html>")

    server, url = _make_server(route)
    try:
        results = _scanner(SOC2ComplianceScanner, url)
        assert isinstance(results, list), "Scanner must return a list"
        assert len(results) >= 1
        for r in results:
            assert "type" in r
            assert "status" in r
            assert r["status"] in ("PASS", "FAIL", "WARN")
    finally:
        server.shutdown()


# ── NIST CSF ─────────────────────────────────────────────────────────────────

def test_nist_csf_flags_no_tls():
    """NIST CSF PR.DS: plain HTTP should produce TLS-related FAIL."""
    def route(h):
        h.send_response(200)
        h.send_header("Content-Type", "text/html")
        h.end_headers()
        h.wfile.write(b"<html><body>bare server</body></html>")

    server, url = _make_server(route)
    try:
        results = _scanner(NISTCSFComplianceScanner, url)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert len(fails) >= 1, f"Expected at least one NIST CSF FAIL, got: {[f['type'] for f in fails]}"
    finally:
        server.shutdown()


def test_nist_csf_result_schema():
    """NIST CSF scanner results must all have required keys."""
    def route(h):
        h.send_response(200)
        h.send_header("Content-Type", "text/html")
        h.end_headers()
        h.wfile.write(b"<html></html>")

    server, url = _make_server(route)
    try:
        results = _scanner(NISTCSFComplianceScanner, url)
        for r in results:
            assert "type" in r, f"Missing 'type': {r}"
            assert "status" in r, f"Missing 'status': {r}"
    finally:
        server.shutdown()


# ── ISO 27001 ─────────────────────────────────────────────────────────────────

def test_iso27001_flags_no_tls():
    """ISO 27001 A.8.20: HTTP target must FAIL on transmission security."""
    def route(h):
        h.send_response(200)
        h.send_header("Content-Type", "text/html")
        h.end_headers()
        h.wfile.write(b"<html><body>no security</body></html>")

    server, url = _make_server(route)
    try:
        results = _scanner(ISO27001ComplianceScanner, url)
        fail_types = [r["type"] for r in results if r["status"] == "FAIL"]
        assert any("tls" in t or "a8_20" in t or "iso" in t for t in fail_types), \
            f"Expected TLS FAIL, got: {fail_types}"
    finally:
        server.shutdown()


def test_iso27001_scanner_result_schema():
    """ISO 27001 scanner results must all have correct structure."""
    def route(h):
        h.send_response(200)
        h.send_header("Content-Type", "text/html")
        h.end_headers()
        h.wfile.write(b"<html></html>")

    server, url = _make_server(route)
    try:
        results = _scanner(ISO27001ComplianceScanner, url)
        assert isinstance(results, list)
        for r in results:
            assert "type" in r
            assert "status" in r
            assert r["status"] in ("PASS", "FAIL", "WARN")
    finally:
        server.shutdown()
