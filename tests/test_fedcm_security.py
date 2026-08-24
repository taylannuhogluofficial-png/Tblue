"""Tests for FedCMSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.fedcm_security import FedCMSecurityScanner


def _scanner():
    s = FedCMSecurityScanner.__new__(FedCMSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestIdPFromParam:
    def test_idp_url_from_param_fails(self):
        s = _scanner()
        body = "navigator.credentials.get({identity: {configURL: searchParams.get('idp'), clientId: 'app'}})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "fedcm_idp_url_from_param" in types


class TestTokenExfil:
    def test_token_exfiltrated_fails(self):
        s = _scanner()
        body = "const cred = await navigator.credentials.get({identity: {configURL: '/idp'}})\nconst c = cred as IdentityCredential\nconst tok = c.token\nsendBeacon('/collect', tok)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "fedcm_token_exfiltrated" in types


class TestAutoSignIn:
    def test_silent_auto_signin_warns(self):
        s = _scanner()
        body = "navigator.credentials.get({identity: {configURL: '/idp', mediation: 'silent', clientId: 'app'}})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "fedcm_silent_auto_signin" in types


class TestNotUsed:
    def test_no_fedcm_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "fedcm_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
