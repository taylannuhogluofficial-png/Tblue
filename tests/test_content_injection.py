"""Tests for tblue.scanner.content_injection."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.content_injection import ContentInjectionScanner


def _scanner():
    session = MagicMock()
    return ContentInjectionScanner(session)


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
        results = s.scan("https://example.com/?q=hello")
    assert any(r["status"] == "PASS" for r in results)


# ── No reflectable params → PASS ─────────────────────────────────────────────

def test_no_params_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        results = s.scan("https://example.com/?page=1&limit=20")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
    assert any("no reflectable" in r["type"].lower() for r in passes)


# ── Unescaped HTML in response → FAIL ────────────────────────────────────────

def test_html_injection_fails():
    s = _scanner()
    clean = _resp(200, "<html><p>No results for: test</p></html>")
    injected = _resp(200,
        '<html><p>No results for: '
        '<div class="tblue_html_probe">TblueTest</div>'
        '</p></html>')

    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean
        if "tblue_html_probe" in url or "TblueTest" in url or "div+class" in url:
            return injected
        return clean

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?q=test")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("html" in r["type"].lower() and "injection" in r["type"].lower()
               for r in fails)


# ── Encoded HTML in response → PASS ──────────────────────────────────────────

def test_encoded_html_passes():
    s = _scanner()
    clean = _resp(200, "<html><p>Welcome</p></html>")
    encoded = _resp(200,
        '<html><p>Search: &lt;div class=&quot;tblue_html_probe&quot;&gt;'
        'TblueTest&lt;/div&gt;</p></html>')

    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean
        return encoded  # Properly encoded → no injection

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?q=test")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not fails  # No FAIL for properly encoded output


# ── CSS injection → WARN ──────────────────────────────────────────────────────

def test_css_injection_warns():
    s = _scanner()
    clean = _resp(200, "<html><p>Hello</p></html>")
    css_injected = _resp(200,
        '<html><b class="tblue_html_probe">injected</b></html>')

    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean
        return css_injected

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?search=test")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("css" in r["type"].lower() or "injection" in r["type"].lower()
               for r in warns)


# ── GET returns None on probe → no crash ─────────────────────────────────────

def test_probe_none_no_crash():
    s = _scanner()
    call_count = [0]

    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, "<html></html>")
        return None

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?q=test")
    assert isinstance(results, list)


# ── Value reflected in body → param collected ────────────────────────────────

def test_collect_by_reflection():
    s = _scanner()
    # The value "hello" appears in the body — param "custom" should be collected
    body = '<html><p>Your search for "hello" returned 0 results.</p></html>'
    params = s._collect_reflectable_params(
        "https://example.com/?custom=hello", body
    )
    assert "custom" in params
