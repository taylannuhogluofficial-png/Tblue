"""Tests for VibrationAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.vibration_api_security import VibrationAPISecurityScanner


def _scanner():
    s = VibrationAPISecurityScanner.__new__(VibrationAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestFromURLParam:
    def test_vibrate_from_url_param_fails(self):
        s = _scanner()
        # _VIB_URL_PARAM_RE: navigator.vibrate([^)]*searchParams — searchParams before first )
        body = "navigator.vibrate(searchParams.get('pattern'))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "vibration_from_url_param" in types


class TestRapidLoop:
    def test_vibrate_in_interval_warns(self):
        s = _scanner()
        body = "setInterval(() => { navigator.vibrate(200) }, 100)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "vibration_rapid_loop" in types


class TestExcessiveDuration:
    def test_very_long_vibration_warns(self):
        s = _scanner()
        body = "navigator.vibrate(60000)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "vibration_excessive_duration" in types


class TestCovertChannel:
    def test_covert_haptic_channel_fails(self):
        s = _scanner()
        # _VIB_COVERT_RE: navigator.vibrate([^)]*token/cookie before first )
        body = "navigator.vibrate(token.length * 100)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "vibration_covert_channel" in types


class TestNotUsed:
    def test_no_vibration_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "vibration_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
