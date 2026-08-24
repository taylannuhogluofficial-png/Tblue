"""Tests for CORSPolicyAdvancedScanner."""
from unittest.mock import MagicMock
from tblue.scanner.cors_policy_advanced import CORSPolicyAdvancedScanner


def _scanner():
    s = CORSPolicyAdvancedScanner.__new__(CORSPolicyAdvancedScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_cors_wildcard_with_credentials():
    s = _scanner()
    s.http.get.return_value = _resp(headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    })
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "cors_wildcard_with_credentials" in types


def test_cors_null_origin_allowed():
    s = _scanner()
    s.http.get.return_value = _resp(headers={
        "Access-Control-Allow-Origin": "null",
    })
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "cors_null_origin_allowed" in types


def test_cors_allow_destructive_methods():
    s = _scanner()
    s.http.get.return_value = _resp(headers={
        "Access-Control-Allow-Origin": "https://trusted.com",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
    })
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "cors_allow_destructive_methods" in types


def test_cors_expose_sensitive_request_headers():
    s = _scanner()
    s.http.get.return_value = _resp(headers={
        "Access-Control-Allow-Origin": "https://app.example.com",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Api-Key",
    })
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "cors_expose_sensitive_request_headers" in types


def test_cors_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No CORS headers</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "cors_policy_advanced_not_used"
    assert results[0]["status"] == "PASS"
