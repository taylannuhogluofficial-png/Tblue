"""Tests for advanced CSP analysis (report-uri, frame-ancestors, base-uri, Trusted Types)."""

from unittest.mock import MagicMock
from tblue.scanner.csp_advanced import CSPAdvancedScanner


def _scanner(csp_header="", csp_ro="", html="", status=200):
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = status
        resp.text = html
        resp.headers = {}
        if csp_header:
            resp.headers["Content-Security-Policy"] = csp_header
        if csp_ro:
            resp.headers["Content-Security-Policy-Report-Only"] = csp_ro
        return resp

    session.request.side_effect = fake_request
    return CSPAdvancedScanner(session)


_FULL_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "upgrade-insecure-requests; "
    "report-uri /csp-report"
)


# ── Report endpoint ───────────────────────────────────────────────────────────

def test_report_uri_configured_passes():
    scanner = _scanner(csp_header="default-src 'self'; report-uri /csp-report")
    results = scanner.scan("https://example.com")
    assert any("violation reporting configured" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_report_to_configured_passes():
    scanner = _scanner(csp_header="default-src 'self'; report-to csp-endpoint")
    results = scanner.scan("https://example.com")
    assert any("violation reporting configured" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_no_report_endpoint_warns():
    scanner = _scanner(csp_header="default-src 'self'; script-src 'self'")
    results = scanner.scan("https://example.com")
    assert any("no violation reporting" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


# ── frame-ancestors ───────────────────────────────────────────────────────────

def test_frame_ancestors_none_passes():
    scanner = _scanner(csp_header="default-src 'self'; frame-ancestors 'none'")
    results = scanner.scan("https://example.com")
    assert any("frame-ancestors 'none'" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_frame_ancestors_self_passes():
    scanner = _scanner(csp_header="default-src 'self'; frame-ancestors 'self'")
    results = scanner.scan("https://example.com")
    assert any("frame-ancestors 'self'" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_frame_ancestors_missing_warns():
    scanner = _scanner(csp_header="default-src 'self'; script-src 'self'")
    results = scanner.scan("https://example.com")
    assert any("frame-ancestors directive missing" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


# ── base-uri ──────────────────────────────────────────────────────────────────

def test_base_uri_configured_passes():
    scanner = _scanner(csp_header="default-src 'self'; base-uri 'self'")
    results = scanner.scan("https://example.com")
    assert any("base-uri restriction configured" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_base_uri_missing_warns():
    scanner = _scanner(csp_header="default-src 'self'")
    results = scanner.scan("https://example.com")
    assert any("base-uri not restricted" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


# ── form-action ───────────────────────────────────────────────────────────────

def test_form_action_configured_passes():
    scanner = _scanner(csp_header="default-src 'self'; form-action 'self'")
    results = scanner.scan("https://example.com")
    assert any("form-action restriction configured" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_form_action_missing_warns():
    scanner = _scanner(csp_header="default-src 'self'")
    results = scanner.scan("https://example.com")
    assert any("form-action not restricted" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


# ── Report-Only mode ──────────────────────────────────────────────────────────

def test_report_only_warns():
    scanner = _scanner(csp_ro="default-src 'self'")
    results = scanner.scan("https://example.com")
    assert any("report-only mode" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


# ── Meta CSP ─────────────────────────────────────────────────────────────────

def test_meta_csp_warns():
    html = '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert any("meta" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Trusted Types ─────────────────────────────────────────────────────────────

def test_trusted_types_passes():
    scanner = _scanner(csp_header="default-src 'self'; require-trusted-types-for 'script'")
    results = scanner.scan("https://example.com")
    assert any("trusted types" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ── No CSP ────────────────────────────────────────────────────────────────────

def test_no_csp_returns_empty():
    scanner = _scanner()
    results = scanner.scan("https://example.com")
    assert results == []
