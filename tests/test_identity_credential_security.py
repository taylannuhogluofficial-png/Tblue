"""Tests for IdentityCredentialSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.identity_credential_security import IdentityCredentialSecurityScanner


def _scanner():
    s = IdentityCredentialSecurityScanner.__new__(IdentityCredentialSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_identity_credential_token_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const cred = await navigator.credentials.get({digital: {providers: [{...}]}})\n"
        "const IdentityCredential = cred\n"
        "const token = IdentityCredential.token\n"
        "fetch('/log', {body: token})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "identity_credential_token_exfiltrated" in types


def test_identity_credential_provider_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "credentials.get({digital: {providers: [{protocol: 'openid4vp', url: searchParams.get('provider')}]}})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "identity_credential_provider_from_param" in types


def test_identity_credential_silent_request():
    s = _scanner()
    s.http.get.return_value = _resp(
        "credentials.get({digital: {providers: [{protocol: 'mdoc'}]}, mediation: 'silent'})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "identity_credential_silent_request" in types


def test_identity_credential_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No identity API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "identity_credential_not_used"
    assert results[0]["status"] == "PASS"


def test_identity_credential_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "identity_credential_not_used"
