"""Tests for OAuthMisconfigurationPassiveScanner."""
from unittest.mock import MagicMock
from tblue.scanner.oauth_misconfiguration_passive import OAuthMisconfigurationPassiveScanner


def _scanner():
    s = OAuthMisconfigurationPassiveScanner.__new__(OAuthMisconfigurationPassiveScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_token_in_url():
    s = _scanner()
    s.http.get.return_value = _resp(
        '{"status": "authenticated"}'
    )
    results = s.scan("http://example.com/callback?access_token=eyJhbGciOiJIUzI1NiJ9abc123")
    types = [r["type"] for r in results]
    assert "oauth_token_in_url" in types


def test_client_secret_in_response():
    s = _scanner()
    s.http.get.return_value = _resp(
        '{"client_id": "app123", "client_secret": "super_secret_value_here", "scope": "read"}'
    )
    results = s.scan("http://example.com/oauth/config")
    types = [r["type"] for r in results]
    assert "oauth_client_secret_in_response" in types


def test_implicit_flow():
    s = _scanner()
    s.http.get.return_value = _resp(
        'redirect to /authorize?response_type=token&client_id=abc&scope=read'
    )
    results = s.scan("http://example.com/login")
    types = [r["type"] for r in results]
    assert "oauth_implicit_flow_detected" in types


def test_oauth_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Regular page</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "oauth_misconfiguration_not_used"
    assert results[0]["status"] == "PASS"


def test_oauth_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "oauth_misconfiguration_not_used"
