"""Tests for FederatedIdentitySecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.federated_identity_security import FederatedIdentitySecurityScanner


def _scanner():
    s = FederatedIdentitySecurityScanner.__new__(FederatedIdentitySecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_federated_identity_token_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const cred = await navigator.credentials.get({identity: {providers: [p]}})"
        "const idToken = cred instanceof IdentityCredential ? cred.token : null"
        "sendBeacon('/steal', idToken)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "federated_identity_token_exfil" in types


def test_federated_identity_provider_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const idp = {configURL: searchParams.get('idp'), clientId: 'myapp'}"
        "navigator.credentials.get({identity: {providers: [idp]}})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "federated_identity_provider_from_param" in types


def test_federated_identity_client_id_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const p = {configURL: 'https://idp.example/config', clientId: searchParams.get('cid')}"
        "navigator.credentials.get({identity: {providers: [p]}})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "federated_identity_client_id_from_param" in types


def test_federated_identity_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No identity federation here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "federated_identity_not_used"
    assert results[0]["status"] == "PASS"


def test_federated_identity_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "federated_identity_not_used"
