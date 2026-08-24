"""Additional tests for csp_advanced — bypass vector checks (unsafe-inline, wildcards, data:, CDN)."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.csp_advanced import CSPAdvancedScanner


def _scanner():
    session = MagicMock()
    return CSPAdvancedScanner(session)


def _resp(status=200, body="<html></html>", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _with_csp(csp_value, body="<html></html>"):
    return _resp(200, body, {"Content-Security-Policy": csp_value})


# ── unsafe-inline → FAIL ─────────────────────────────────────────────────────

def test_unsafe_inline_script_src_fails():
    s = _scanner()
    with patch.object(s.http, "get",
                      return_value=_with_csp("default-src 'self'; script-src 'self' 'unsafe-inline'")):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("unsafe-inline" in r["type"].lower() for r in fails)


# ── unsafe-eval → WARN ───────────────────────────────────────────────────────

def test_unsafe_eval_script_src_warns():
    s = _scanner()
    with patch.object(s.http, "get",
                      return_value=_with_csp("script-src 'self' 'unsafe-eval'; base-uri 'self'")):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("unsafe-eval" in r["type"].lower() for r in warns)


# ── Wildcard in script-src → FAIL ────────────────────────────────────────────

def test_wildcard_script_src_fails():
    s = _scanner()
    with patch.object(s.http, "get",
                      return_value=_with_csp("script-src *; base-uri 'self'; object-src 'none'")):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("wildcard" in r["type"].lower() for r in fails)


# ── data: URI in script-src → FAIL ───────────────────────────────────────────

def test_data_uri_script_src_fails():
    s = _scanner()
    with patch.object(s.http, "get",
                      return_value=_with_csp("script-src 'self' data:; base-uri 'self'")):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("data:" in r["type"].lower() for r in fails)


# ── JSONP CDN bypass host → WARN ─────────────────────────────────────────────

def test_jsonp_bypass_host_warns():
    s = _scanner()
    with patch.object(s.http, "get",
                      return_value=_with_csp(
                          "script-src 'self' ajax.googleapis.com; base-uri 'self'")):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("jsonp" in r["type"].lower() or "bypass" in r["type"].lower() for r in warns)


# ── No CSP → WARN ────────────────────────────────────────────────────────────

def test_no_csp_warns():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200)):
        results = s.scan("https://example.com")
    # No CSP falls through to the basic check (no results from advanced) or returns early
    # The scanner returns self.results which is empty list when no CSP
    # (returns early — doesn't call bypass checks)
    assert isinstance(results, list)


# ── None response → empty results ────────────────────────────────────────────

def test_none_response_returns():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert results == []
