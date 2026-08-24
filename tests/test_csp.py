"""
Tests for CSP deep analyzer.
"""

import pytest
from unittest.mock import MagicMock
from tblue.scanner.csp import CSPScanner


def make_scanner(csp_value: str = "", html: str = "<html><head></head><body></body></html>") -> CSPScanner:
    session      = MagicMock()
    resp         = MagicMock()
    resp.headers = {"content-security-policy": csp_value} if csp_value else {}
    resp.text    = html
    resp.url     = "https://example.com"
    session.request.return_value = resp
    return CSPScanner(session)


def test_missing_csp_fails():
    scanner = make_scanner("")
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "FAIL" and "missing" in r["type"].lower() for r in results)


def test_strong_csp_passes():
    csp = "default-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    scanner = make_scanner(csp)
    results = scanner.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert len(fails) == 0


def test_unsafe_inline_flagged():
    csp = "default-src 'self' 'unsafe-inline'"
    scanner = make_scanner(csp)
    results = scanner.scan("https://example.com")
    assert any("unsafe-inline" in r.get("detail", "") for r in results if r["status"] == "FAIL")


def test_unsafe_eval_flagged():
    csp = "default-src 'self' 'unsafe-eval'"
    scanner = make_scanner(csp)
    results = scanner.scan("https://example.com")
    assert any("unsafe-eval" in r.get("detail", "") for r in results if r["status"] == "FAIL")


def test_wildcard_flagged():
    csp = "default-src *"
    scanner = make_scanner(csp)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "FAIL" for r in results)


def test_missing_frame_ancestors_warns():
    csp = "default-src 'self'"
    scanner = make_scanner(csp)
    results = scanner.scan("https://example.com")
    assert any("frame-ancestors" in r["type"] and r["status"] == "WARN" for r in results)


def test_missing_base_uri_warns():
    csp = "default-src 'self'; frame-ancestors 'none'"
    scanner = make_scanner(csp)
    results = scanner.scan("https://example.com")
    assert any("base-uri" in r["type"] and r["status"] == "WARN" for r in results)


def test_missing_form_action_warns():
    csp = "default-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    scanner = make_scanner(csp)
    results = scanner.scan("https://example.com")
    assert any("form-action" in r["type"] and r["status"] == "WARN" for r in results)


def test_summary_result_present():
    csp = "default-src 'self'"
    scanner = make_scanner(csp)
    results = scanner.scan("https://example.com")
    assert any("summary" in r["type"].lower() for r in results)


def test_failed_request_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("Timeout")
    scanner = CSPScanner(session, retries=1)
    results = scanner.scan("https://example.com")
    assert results == []


# ── Dangerous URI schemes ─────────────────────────────────────────────────────

def test_data_uri_in_script_src_fails():
    csp = "script-src 'self' data:"
    scanner = make_scanner(csp)
    results = scanner.scan("https://example.com")
    assert any("data:" in r.get("detail", "") and r["status"] == "FAIL" for r in results)


def test_http_scheme_in_script_src_fails():
    csp = "script-src 'self' http:"
    scanner = make_scanner(csp)
    results = scanner.scan("https://example.com")
    assert any("http:" in r.get("detail", "") and r["status"] == "FAIL" for r in results)


# ── frame-ancestors wildcard (FAIL) vs. missing (WARN) ───────────────────────

def test_frame_ancestors_wildcard_fails():
    csp = "default-src 'self'; frame-ancestors *"
    scanner = make_scanner(csp)
    results = scanner.scan("https://example.com")
    assert any("frame-ancestors" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_frame_ancestors_configured_passes():
    csp = "default-src 'self'; frame-ancestors 'none'"
    scanner = make_scanner(csp)
    results = scanner.scan("https://example.com")
    assert any("frame-ancestors" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ── Nonce quality ─────────────────────────────────────────────────────────────

def test_static_nonce_fails():
    # Short, predictable nonce (matches _STATIC_NONCE pattern)
    csp = "script-src 'self' 'nonce-abc123'"
    scanner = make_scanner(csp)
    results = scanner.scan("https://example.com")
    assert any("nonce" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_strong_nonce_passes():
    # Long, random-looking nonce — should not be flagged as static
    csp = "script-src 'self' 'nonce-r4nd0mN0nce3xAmpl3XYZ789abcdef=='"
    scanner = make_scanner(csp)
    results = scanner.scan("https://example.com")
    assert not any("nonce" in r["type"].lower() and r["status"] == "FAIL" for r in results)


# ── Violation reporting ───────────────────────────────────────────────────────

def test_no_violation_reporting_warns():
    csp = "default-src 'self'"
    scanner = make_scanner(csp)
    results = scanner.scan("https://example.com")
    assert any("no violation reporting" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


def test_report_uri_configured_passes():
    csp = "default-src 'self'; report-uri /csp-report"
    scanner = make_scanner(csp)
    results = scanner.scan("https://example.com")
    assert any("violation reporting" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_report_to_configured_passes():
    csp = "default-src 'self'; report-to csp-endpoint"
    scanner = make_scanner(csp)
    results = scanner.scan("https://example.com")
    assert any("violation reporting" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


# ── Bypass CDN sources ────────────────────────────────────────────────────────

def test_cdnjs_in_script_src_warns():
    csp = "script-src 'self' cdnjs.cloudflare.com"
    scanner = make_scanner(csp)
    results = scanner.scan("https://example.com")
    assert any("bypass source" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_googleapis_in_script_src_warns():
    csp = "script-src 'self' ajax.googleapis.com"
    scanner = make_scanner(csp)
    results = scanner.scan("https://example.com")
    assert any("bypass source" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Meta tag CSP ──────────────────────────────────────────────────────────────

def test_meta_tag_csp_warns():
    html = '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">'
    scanner = make_scanner("", html=html)
    results = scanner.scan("https://example.com")
    assert any("meta tag" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_no_meta_tag_csp_when_header_present():
    # No meta tag — should not emit the meta-tag warning
    scanner = make_scanner("default-src 'self'")
    results = scanner.scan("https://example.com")
    assert not any("meta tag" in r["type"].lower() and r["status"] == "WARN" for r in results)
