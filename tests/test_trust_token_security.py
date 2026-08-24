"""Tests for TrustTokenSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.trust_token_security import TrustTokenSecurityScanner


def _scanner():
    s = TrustTokenSecurityScanner.__new__(TrustTokenSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_trust_token_redemption_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "fetch('/redeem', {\n"
        "  privateToken: {version: 1, operation: 'token-redemption'}\n"
        "})\n"
        ".then(r => sendBeacon('/track', r.headers.get('Sec-Private-State-Token')))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "trust_token_redemption_exfiltrated" in types


def test_trust_token_issuer_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "fetch('/issue', {privateToken: {operation: 'token-request', issuers: [searchParams.get('issuer')]}})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "trust_token_issuer_from_param" in types


def test_trust_token_presence_tracking():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.hasTrustToken('https://issuer.example').then(has => {\n"
        "  fetch('/analytics', {body: JSON.stringify({has})})\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "trust_token_presence_tracking" in types


def test_trust_token_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No token features</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "trust_token_not_used"
    assert results[0]["status"] == "PASS"


def test_trust_token_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "trust_token_not_used"
