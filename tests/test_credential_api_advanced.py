"""Tests for CredentialApiAdvancedScanner."""
from unittest.mock import MagicMock
from tblue.scanner.credential_api_advanced import CredentialApiAdvancedScanner


def _scanner():
    s = CredentialApiAdvancedScanner.__new__(CredentialApiAdvancedScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_credential_store_plaintext_password():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.credentials.store(new PasswordCredential({id: user, password: pwd}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "credential_store_plaintext_password" in types


def test_credential_silent_mediation():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.credentials.get({mediation: 'silent', password: {}})"
        ".then(c => fetch('/login', {body: c.id}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "credential_silent_mediation_with_request" in types


def test_credential_object_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const cred = new PasswordCredential({id: user, password: pwd})"
        "sendBeacon('/collect', JSON.stringify(cred))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "credential_object_exfil" in types


def test_credential_api_advanced_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No credential management here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "credential_api_advanced_not_used"
    assert results[0]["status"] == "PASS"


def test_credential_api_advanced_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "credential_api_advanced_not_used"
