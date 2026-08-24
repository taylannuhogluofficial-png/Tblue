"""Tests for tblue.scanner.api_auth_security."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.api_auth_security import APIAuthSecurityScanner


def _scanner():
    session = MagicMock()
    return APIAuthSecurityScanner(session)


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


# ── Basic auth over HTTP → FAIL ───────────────────────────────────────────────

def test_basic_auth_over_http_fails():
    s = _scanner()
    with patch.object(s.http, "get",
                      return_value=_resp(401, "", {"WWW-Authenticate": "Basic realm=\"API\""})):
        results = s.scan("http://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("basic" in r["type"].lower() and "http" in r["type"].lower() for r in fails)


# ── API key in URL → WARN ─────────────────────────────────────────────────────

def test_api_key_in_url_warns():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        results = s.scan("https://example.com/data?api_key=sk_live_abc123")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("api key" in r["type"].lower() for r in warns)


# ── Unauthenticated access to /api/users → FAIL ──────────────────────────────

def test_unauthenticated_api_access_fails():
    s = _scanner()
    user_data = '{"id": 1, "email": "admin@example.com", "role": "admin"}'

    def get_side_effect(url, **kwargs):
        if "/api/users" in url:
            return _resp(200, user_data)
        return _resp(200, "<html></html>")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("accessible without authentication" in r["type"].lower() for r in fails)


# ── API returns 200 with error body → WARN ────────────────────────────────────

def test_api_200_with_error_body_warns():
    s = _scanner()
    error_body = '{"status": "error", "message": "unauthorized"}'

    def get_side_effect(url, **kwargs):
        if "/api/users" in url or "/api/profile" in url or "/api/me" in url:
            return _resp(200, error_body)
        return _resp(200, "<html></html>")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("200" in r["type"] and "error" in r["type"].lower() for r in warns)


# ── 401 without WWW-Authenticate → WARN ──────────────────────────────────────

def test_401_without_www_authenticate_warns():
    s = _scanner()
    auth_resp = _resp(401, "Unauthorized", {})  # No WWW-Authenticate

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return auth_resp
        return _resp(403, "")  # API paths return 403

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("www-authenticate" in r["type"].lower() for r in warns)


# ── Clean API (all 401/403) → PASS ───────────────────────────────────────────

def test_clean_api_passes():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(403, "Forbidden")):
        results = s.scan("https://example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


# ── HTTPS Basic auth is OK → no fail ─────────────────────────────────────────

def test_basic_auth_over_https_ok():
    s = _scanner()
    with patch.object(s.http, "get",
                      return_value=_resp(401, "",
                                         {"WWW-Authenticate": "Basic realm=\"API\""})):
        results = s.scan("https://example.com")  # HTTPS!
    # Basic over HTTPS should not produce FAIL (only potential WARN for other issues)
    fails = [r for r in results if r["status"] == "FAIL" and "basic" in r["type"].lower()]
    assert not fails
