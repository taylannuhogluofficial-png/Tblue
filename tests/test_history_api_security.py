"""Tests for HistoryAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.history_api_security import HistoryAPISecurityScanner


def _scanner():
    s = HistoryAPISecurityScanner.__new__(HistoryAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestURLFromParam:
    def test_pushstate_url_from_param_warns(self):
        s = _scanner()
        body = "history.pushState({}, '', searchParams.get('url'))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "history_api_url_from_param" in types


class TestExternalURL:
    def test_external_url_pushed_fails(self):
        s = _scanner()
        body = "history.pushState(null, '', 'https://phishing.example.com/login')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "history_api_external_url_push" in types


class TestSensitiveState:
    def test_sensitive_state_in_history_warns(self):
        s = _scanner()
        body = "history.pushState({token: authToken, auth: sessionKey}, '', '/dashboard')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "history_api_sensitive_state" in types


class TestNotUsed:
    def test_no_history_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "history_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
