"""Tests for EyeDropperAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.eyedropper_api_security import EyeDropperAPISecurityScanner


def _scanner():
    s = EyeDropperAPISecurityScanner.__new__(EyeDropperAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestAutoTriggered:
    def test_load_trigger_fails(self):
        s = _scanner()
        body = "window.addEventListener('load', async () => { const ed = new EyeDropper(); await ed.open(); })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "eyedropper_auto_triggered" in types


class TestColorTransmitted:
    def test_color_sent_to_server_warns(self):
        s = _scanner()
        # _ED_SEND_RE: sRGBHex before fetch/sendBeacon within 200 non-semicolon chars (no ;)
        body = "const ed = new EyeDropper()\nconst color = result.sRGBHex\nfetch('/log', {body: color})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "eyedropper_color_transmitted" in types


class TestAnalyticsShared:
    def test_color_to_analytics_fails(self):
        s = _scanner()
        body = "const ed = new EyeDropper(); const c = await ed.open(); analytics('color', {sRGBHex: c.sRGBHex})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "eyedropper_color_shared_with_analytics" in types


class TestNotUsed:
    def test_no_eyedropper_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "eyedropper_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
