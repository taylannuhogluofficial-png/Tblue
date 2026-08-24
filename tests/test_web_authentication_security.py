"""Tests for WebAuthenticationSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.web_authentication_security import WebAuthenticationSecurityScanner


def _scanner():
    s = WebAuthenticationSecurityScanner.__new__(WebAuthenticationSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_webauthn_attestation_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const cred = await navigator.credentials.create(opts)"
        "const authData = cred.response.authenticatorData"
        "analytics('webauthn', {data: authData})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "webauthn_attestation_exfil" in types


def test_webauthn_client_data_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const resp = await navigator.credentials.get(opts)"
        "const cd = resp.response.clientDataJSON"
        "fetch('/log', {body: cd})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "webauthn_client_data_exfil" in types


def test_webauthn_options_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const cred = await navigator.credentials.get({publicKey: {rpId: searchParams.get('rpid')}})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "webauthn_options_from_param" in types


def test_web_authentication_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No hardware authenticator usage here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "web_authentication_not_used"
    assert results[0]["status"] == "PASS"


def test_web_authentication_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "web_authentication_not_used"
