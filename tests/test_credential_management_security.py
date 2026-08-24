"""Tests for CredentialManagementSecurityScanner."""
import pytest
from unittest.mock import MagicMock
from tblue.scanner.credential_management_security import CredentialManagementSecurityScanner


def _scanner():
    s = CredentialManagementSecurityScanner.__new__(CredentialManagementSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None, url="http://example.com"):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestHardcodedPassword:
    def test_hardcoded_password_fails(self):
        s = _scanner()
        body = """
        const cred = new PasswordCredential({
            id: 'admin',
            password: 'secret123',
        });
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "cred_mgmt_hardcoded_password" in types
        assert any(r["status"] == "FAIL" for r in results)


class TestSilentMediation:
    def test_silent_mediation_warns(self):
        s = _scanner()
        body = """
        const cred = await navigator.credentials.get({
            password: true,
            mediation: 'silent',
        });
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "cred_mgmt_silent_mediation" in types


class TestNoPreventSilentAccess:
    def test_store_without_prevent_silent_warns(self):
        s = _scanner()
        body = """
        const cred = new PasswordCredential(form);
        navigator.credentials.store(cred);
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "cred_mgmt_no_prevent_silent_on_logout" in types

    def test_store_with_prevent_silent_passes(self):
        s = _scanner()
        body = """
        const cred = new PasswordCredential(form);
        navigator.credentials.store(cred);
        function logout() { navigator.credentials.preventSilentAccess(); }
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "cred_mgmt_no_prevent_silent_on_logout" not in types


class TestNotUsed:
    def test_no_credential_management_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "cred_mgmt_not_used"
        assert results[0]["status"] == "PASS"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
