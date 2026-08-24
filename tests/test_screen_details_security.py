"""Tests for ScreenDetailsSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.screen_details_security import ScreenDetailsSecurityScanner


def _scanner():
    s = ScreenDetailsSecurityScanner.__new__(ScreenDetailsSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestDetailsExfil:
    def test_screen_details_exfiltrated_warns(self):
        s = _scanner()
        # _SD_EXFIL_RE: getScreenDetails ... fetch
        body = "window.getScreenDetails().then(sd => fetch('/fp', {body: JSON.stringify(sd)}))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "screen_details_exfiltrated" in types


class TestMonitorCount:
    def test_monitor_count_exfiltrated_warns(self):
        s = _scanner()
        # _SD_MONITOR_COUNT_RE: screens.length (before) ... localStorage (after)
        body = "window.getScreenDetails().then(sd => { const count = sd.screens.length\nlocalStorage.setItem('monitors', count) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "screen_monitor_count_exfiltrated" in types


class TestAutoRequest:
    def test_auto_requested_on_load_warns(self):
        s = _scanner()
        # _SD_AUTO_REQUEST_RE: DOMContentLoaded ... getScreenDetails
        body = "window.addEventListener('DOMContentLoaded', () => window.getScreenDetails())"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "screen_details_auto_requested" in types


class TestNotUsed:
    def test_no_screen_details_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "screen_details_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
