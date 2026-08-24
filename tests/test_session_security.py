"""Tests for tblue.scanner.session_security — Session management scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.session_security import SessionSecurityScanner


def _scanner():
    session = MagicMock()
    return SessionSecurityScanner(session)


def _resp(status=200, body="", cookies=None, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {"content-type": "text/html"}
    r.cookies = cookies or []
    return r


def _cookie(name, value, expires=None):
    c = MagicMock()
    c.name = name
    c.value = value
    c.expires = expires
    return c


def test_no_session_issues_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html>Hello</html>")):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_session_id_in_url_fail():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html>Home</html>")):
        results = s.scan("https://example.com?sessionid=abc123")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("URL" in r["type"] for r in fails)


def test_jsessionid_in_url_fail():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html>App</html>")):
        results = s.scan("https://example.com?jsessionid=ABCDEF1234567890")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_weak_session_token_fail():
    s = _scanner()
    c = _cookie("session", "12345678")  # pure 8-digit hex
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>", cookies=[c])):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("weak" in r["type"].lower() or "predictable" in r["type"].lower() for r in fails)


def test_weak_numeric_session_fail():
    s = _scanner()
    c = _cookie("session", "123456")
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>", cookies=[c])):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_remember_me_cookie_no_expiry_warn():
    s = _scanner()
    c = _cookie("remember_me", "a" * 32, expires=None)
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>", cookies=[c])):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("remember" in r["type"].lower() for r in warns)


def test_login_form_with_get_method_fail():
    s = _scanner()
    body = '<html><form method="get" action="/login"><input name="user"/><input name="pass"/></form></html>'
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("GET" in r["type"] for r in fails)


def test_remember_me_feature_warn():
    s = _scanner()
    body = '<html><input type="checkbox" name="remember_me" /> Remember me</html>'
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("remember" in r["type"].lower() for r in warns)


def test_session_without_logout_warn():
    s = _scanner()
    c = _cookie("session", "a" * 32)
    body = "<html>Dashboard — no logout link here</html>"
    with patch.object(s.http, "get", return_value=_resp(200, body, cookies=[c])):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("logout" in r["type"].lower() for r in warns)


def test_no_response():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_multiple_session_cookies_warn():
    s = _scanner()
    cookies = [
        _cookie("session", "a" * 40),
        _cookie("token", "b" * 40),
        _cookie("auth", "c" * 40),
    ]
    with patch.object(s.http, "get", return_value=_resp(200, '<a href="/logout">Logout</a>',
                                                         cookies=cookies)):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("multiple" in r["type"].lower() for r in warns)
