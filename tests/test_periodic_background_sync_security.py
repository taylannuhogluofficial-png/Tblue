"""Tests for PeriodicBackgroundSyncSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.periodic_background_sync_security import PeriodicBackgroundSyncSecurityScanner


def _scanner():
    s = PeriodicBackgroundSyncSecurityScanner.__new__(PeriodicBackgroundSyncSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestTagFromParam:
    def test_sync_tag_from_url_param_fails(self):
        s = _scanner()
        # _PBS_TAG_FROM_PARAM_RE: periodicSync.register(...searchParams...)
        body = "registration.periodicSync.register(searchParams.get('tag'), {minInterval: 86400000})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "periodic_sync_tag_from_url_param" in types


class TestDataExfil:
    def test_data_exfiltrated_fails(self):
        s = _scanner()
        # _PBS_EXFIL_RE: periodicSync ... fetch ... localStorage
        body = "registration.periodicSync.register('sync')\nself.addEventListener('periodicsync', e => { fetch('/upload', {body: localStorage.getItem('data')}) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "periodic_sync_data_exfiltrated" in types


class TestShortInterval:
    def test_short_interval_warns(self):
        s = _scanner()
        # _PBS_SHORT_INTERVAL_RE: periodicSync.register(...minInterval: 1000...)
        body = "registration.periodicSync.register('heartbeat', {minInterval: 1000})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "periodic_sync_short_interval" in types


class TestNotUsed:
    def test_no_periodic_sync_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "periodic_background_sync_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
