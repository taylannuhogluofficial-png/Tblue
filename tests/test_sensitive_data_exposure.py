"""Tests for tblue.scanner.sensitive_data_exposure."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.sensitive_data_exposure import SensitiveDataExposureScanner


def _scanner():
    session = MagicMock()
    return SensitiveDataExposureScanner(session)


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


# ── Credential in URL → FAIL ─────────────────────────────────────────────────

def test_password_in_url_fails():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        results = s.scan("https://example.com/login?username=alice&password=Secret123")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("password" in r["type"].lower() and "credential" in r["type"].lower()
               for r in fails)


# ── Session token in URL → FAIL ───────────────────────────────────────────────

def test_session_token_in_url_fails():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        results = s.scan("https://example.com/dashboard?PHPSESSID=abc123xyz789")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("session" in r["type"].lower() for r in fails)


# ── PII in URL → WARN ─────────────────────────────────────────────────────────

def test_pii_in_url_warns():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        results = s.scan("https://example.com/search?ssn=123456789")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("pii" in r["type"].lower() or "ssn" in r["type"].lower() for r in warns)


# ── Internal path in response header → WARN ──────────────────────────────────

def test_internal_path_in_header_warns():
    s = _scanner()
    with patch.object(s.http, "get",
                      return_value=_resp(200, "<html></html>",
                                         {"X-Debug-Path": "/var/www/html/app/views/"})):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("internal path" in r["type"].lower() for r in warns)


# ── Token in HTML comment → FAIL ─────────────────────────────────────────────

def test_token_in_html_comment_fails():
    s = _scanner()
    body = '<!-- api_key = sk_live_abc123xyz789 --><html></html>'
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("comment" in r["type"].lower() for r in fails)


# ── Email in HTML comment → WARN ─────────────────────────────────────────────

def test_email_in_html_comment_warns():
    s = _scanner()
    body = '<!-- TODO: contact admin@company.com for issues --><html></html>'
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("email" in r["type"].lower() for r in warns)


# ── Password field without autocomplete=off → WARN ───────────────────────────

def test_password_autocomplete_warns():
    s = _scanner()
    body = '<html><form><input type="password" name="pwd"/></form></html>'
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com/login")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("autocomplete" in r["type"].lower() for r in warns)


# ── Clean page → PASS ─────────────────────────────────────────────────────────

def test_clean_page_passes():
    s = _scanner()
    body = ('<html><form>'
            '<input type="password" name="pwd" autocomplete="current-password"/>'
            '</form></html>')
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com/login")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_credential_in_meta_redirect_fails():
    """Meta-refresh with credential param → FAIL lines 232-251."""
    s = _scanner()
    body = ('<html><head>'
            '<meta http-equiv="refresh" content="0; URL=/dashboard?token=abc123xyz"/>'
            '</head></html>')
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("meta-redirect" in f["type"].lower() or "credential" in f["type"].lower()
               for f in fails)


def test_session_token_in_meta_redirect_fails():
    """Meta-refresh with session param → FAIL lines 232-251 (_SESSION_PARAMS branch)."""
    s = _scanner()
    body = ('<html><head>'
            '<meta http-equiv="refresh" content="0; URL=/home?sessionid=xyz789"/>'
            '</head></html>')
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("meta-redirect" in f["type"].lower() or "credential" in f["type"].lower()
               or "session" in f["type"].lower() for f in fails)
