"""Tests for WindowManagementSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.window_management_security import WindowManagementSecurityScanner


def _scanner():
    s = WindowManagementSecurityScanner.__new__(WindowManagementSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestScreenFingerprinting:
    def test_screen_details_to_analytics_fails(self):
        s = _scanner()
        # _WM_FINGERPRINT_RE: getScreenDetails ... fetch/analytics within 300 non-semicolon chars
        body = "const details = await window.getScreenDetails()\nfetch('/log', {body: details.screens.length})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "window_management_screen_fingerprinting" in types


class TestDataTransmitted:
    def test_screen_details_sent_warns(self):
        s = _scanner()
        # _WM_SEND_RE: screens/screenDetails before fetch within 200 non-semicolon chars
        body = "const sd = await window.getScreenDetails()\nconst screens = sd.screens\nfetch('/info', {body: JSON.stringify(screens)})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "window_management_data_transmitted" in types


class TestNoPermissionHandling:
    def test_no_catch_warns(self):
        s = _scanner()
        body = "const details = await window.getScreenDetails()"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "window_management_no_permission_handling" in types

    def test_with_catch_passes(self):
        s = _scanner()
        body = "try { const d = await window.getScreenDetails() } catch(e) { permission = 'denied' }"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "window_management_no_permission_handling" not in types


class TestNotUsed:
    def test_no_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "window_management_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
