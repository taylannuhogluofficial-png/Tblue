"""Tests for tblue.scanner.crlf_injection — CRLF/response splitting scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.crlf_injection import CRLFInjectionScanner


def _scanner():
    session = MagicMock()
    return CRLFInjectionScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


# ── None response → PASS ──────────────────────────────────────────────────────

def test_no_response_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


# ── URL with no params → PASS ─────────────────────────────────────────────────

def test_no_url_params_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        results = s.scan("https://example.com/")
    assert any(r["status"] == "PASS" for r in results)


# ── CRLF injected header reflected in URL param → FAIL ───────────────────────

def test_crlf_reflected_in_url_param_fails():
    s = _scanner()
    clean_resp = _resp(200, "<html></html>")
    injected_resp = _resp(200, "<html></html>", headers={
        "content-type": "text/html",
        "x-injected": "test",  # The injected header was reflected
    })

    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        # First call: initial page fetch
        if call_count[0] == 1:
            return clean_resp
        # Subsequent calls: injection probe
        return injected_resp

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?q=test")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("crlf" in r["type"].lower() for r in fails)


# ── CRLF via redirect param → FAIL ───────────────────────────────────────────

def test_crlf_via_redirect_param_fails():
    s = _scanner()
    clean_resp = _resp(200, "<html></html>")
    injected_resp = _resp(302, "", headers={
        "location": "https://example.com/\r\nX-Injected: test",
        "x-injected": "test",
    })

    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean_resp
        if "next=" in url or "redirect=" in url or "url=" in url or "return" in url:
            return injected_resp
        return clean_resp

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/login")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("crlf" in r["type"].lower() for r in fails)


# ── CRLF marker reflected in body → WARN ─────────────────────────────────────

def test_crlf_marker_in_body_warns():
    s = _scanner()
    clean_resp = _resp(200, "<html></html>")
    body_reflect = _resp(200, "<html>x-injected test reflected in body</html>")

    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean_resp
        if "next=" in url or "redirect=" in url or "url=" in url or "return" in url:
            return body_reflect
        return clean_resp

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/login")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("crlf" in r["type"].lower() for r in warns)


# ── No injection found → PASS ─────────────────────────────────────────────────

def test_no_crlf_injection_passes():
    s = _scanner()
    clean_resp = _resp(200, "<html></html>", headers={"content-type": "text/html"})
    with patch.object(s.http, "get", return_value=clean_resp):
        results = s.scan("https://example.com/?q=hello&page=1")
    assert any(r["status"] == "PASS" for r in results)


# ── _headers_contain_injection helper ────────────────────────────────────────

def test_headers_contain_injection_detected():
    s = _scanner()
    resp = _resp(200, "", headers={"x-injected": "anything"})
    assert s._headers_contain_injection(resp) is True


def test_headers_no_injection():
    s = _scanner()
    resp = _resp(200, "", headers={"content-type": "text/html", "x-custom": "value"})
    assert s._headers_contain_injection(resp) is False
