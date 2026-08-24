"""Tests for tblue.scanner.ldap_injection — LDAP injection scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.ldap_injection import LDAPinjectionScanner


def _scanner():
    session = MagicMock()
    return LDAPinjectionScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


_LOGIN_FORM = ('<html><form method="post" action="/login">'
               '<input type="text" name="username"/>'
               '<input type="password" name="password"/>'
               '</form></html>')

# ── None response → PASS ──────────────────────────────────────────────────────

def test_no_response_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


# ── No login form → PASS ──────────────────────────────────────────────────────

def test_no_login_form_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(404, "")):
        results = s.scan("https://example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
    assert any("no login" in r["type"].lower() for r in passes)


# ── LDAP error in baseline response → WARN ────────────────────────────────────

def test_ldap_error_in_baseline_warns():
    s = _scanner()
    ldap_error_body = (_LOGIN_FORM + '<p>javax.naming.NamingException: LDAP Error</p>')
    login_failure = "Invalid credentials. LDAP bind failed: cn=invalid, dc=example, dc=com"

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, ldap_error_body)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", return_value=_resp(200, login_failure)):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("ldap" in r["type"].lower() for r in warns)


# ── Auth bypass via LDAP wildcard → FAIL ─────────────────────────────────────

def test_auth_bypass_fails():
    s = _scanner()
    fail_body = "Invalid credentials. Please try again."
    success_body = "<html><h1>Welcome, Admin! Logout</h1></html>"

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, _LOGIN_FORM)
        return _resp(404, "")

    def post_side_effect(url, data=None, **kwargs):
        username = (data or {}).get("username", "")
        if username in ("*", "*)(&", "admin)(&(password=*))"):
            return _resp(200, success_body)  # Bypass!
        return _resp(200, fail_body)

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", side_effect=post_side_effect):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("ldap" in r["type"].lower() or "bypass" in r["type"].lower() for r in fails)


# ── LDAP error triggered by probe (not baseline) → WARN ──────────────────────

def test_ldap_error_from_probe_warns():
    s = _scanner()
    fail_body = "Invalid credentials."
    ldap_error = "LDAP search error: invalid filter: uid=*)(&"

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, _LOGIN_FORM)
        return _resp(404, "")

    call_count = [0]
    def post_side_effect(url, data=None, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, fail_body)  # Baseline
        return _resp(200, ldap_error)  # Probe triggers LDAP error

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", side_effect=post_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("ldap" in r["type"].lower() for r in warns)


# ── POST returns None → no crash ─────────────────────────────────────────────

def test_post_none_no_crash():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, _LOGIN_FORM)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", return_value=None):
        results = s.scan("https://example.com")
    assert isinstance(results, list)


# ── Clean login → PASS ────────────────────────────────────────────────────────

def test_clean_login_passes():
    s = _scanner()
    fail_body = "Invalid username or password."

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, _LOGIN_FORM)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect), \
         patch.object(s.http, "post", return_value=_resp(200, fail_body)):
        results = s.scan("https://example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
