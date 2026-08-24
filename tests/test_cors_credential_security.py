"""Tests for CORSCredentialSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.cors_credential_security import CORSCredentialSecurityScanner


def _scanner():
    s = CORSCredentialSecurityScanner.__new__(CORSCredentialSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_cors_credentials_with_wildcard():
    s = _scanner()
    s.http.get.return_value = _resp(
        "fetch('/api', {credentials: 'include', mode: 'cors'})"
        ".then(r => r.json().then(d => allowedOrigins.push('*')))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "cors_credentials_with_wildcard" in types


def test_cors_credentials_to_third_party():
    s = _scanner()
    s.http.get.return_value = _resp(
        "fetch('https://analytics.third-party.com/track', {credentials: 'include', method: 'POST'})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "cors_credentials_to_third_party" in types


def test_cors_xhr_credentials_to_external():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const xhr = new XMLHttpRequest()"
        "xhr.withCredentials = true"
        "xhr.open('POST', 'https://analytics.cdn.example.com/collect')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "cors_xhr_credentials_to_external" in types


def test_cors_credential_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No cross-origin fetch requests here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "cors_credential_not_used"
    assert results[0]["status"] == "PASS"


def test_cors_credential_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "cors_credential_not_used"
