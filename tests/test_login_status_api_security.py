"""Tests for LoginStatusAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.login_status_api_security import LoginStatusAPISecurityScanner


def _scanner():
    s = LoginStatusAPISecurityScanner.__new__(LoginStatusAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestStatusExfil:
    def test_login_status_exfiltrated_warns(self):
        s = _scanner()
        body = "const loginStatus = navigator.login\nfetch('/track', {body: JSON.stringify({status: loginStatus})})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "login_status_exfiltrated" in types


class TestParamControlled:
    def test_login_status_from_param_fails(self):
        s = _scanner()
        body = "navigator.login.setStatus(searchParams.get('state'))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "login_status_from_url_param" in types


class TestForcedOnLoad:
    def test_forced_login_on_load_warns(self):
        s = _scanner()
        body = "window.addEventListener('DOMContentLoaded', () => navigator.login.setStatus('logged-in'))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "login_status_forced_on_load" in types


class TestNotUsed:
    def test_no_login_status_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "login_status_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
