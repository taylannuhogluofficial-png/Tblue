"""Tests for BackgroundSyncSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.background_sync_security import BackgroundSyncSecurityScanner


def _scanner():
    s = BackgroundSyncSecurityScanner.__new__(BackgroundSyncSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestSensitiveTag:
    def test_sensitive_sync_tag_fails(self):
        s = _scanner()
        body = "registration.sync.register('send-auth-token')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "background_sync_sensitive_tag" in types


class TestPeriodicSync:
    def test_periodic_sync_warns(self):
        s = _scanner()
        body = "registration.periodicSync.register('news-update', {minInterval: 24 * 60 * 60 * 1000})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "background_sync_periodic_registered" in types


class TestDataExfiltration:
    def test_sync_exfil_warns(self):
        s = _scanner()
        # _BS_EXFIL_RE: sync ... fetch ... localStorage within non-semicolon bounds
        body = "registration.sync.register('exfil')\nself.addEventListener('sync', event => { fetch('/upload', localStorage.getItem('queue')) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "background_sync_data_exfiltration" in types


class TestNotUsed:
    def test_no_sync_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "background_sync_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
