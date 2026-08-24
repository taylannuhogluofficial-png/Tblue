"""Tests for DeviceMotionSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.device_motion_security import DeviceMotionSecurityScanner


def _scanner():
    s = DeviceMotionSecurityScanner.__new__(DeviceMotionSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestKeylogging:
    def test_keypress_motion_correlation_fails(self):
        s = _scanner()
        body = "document.addEventListener('keydown', e => { const accel = event.acceleration; logKey(accel) }); window.addEventListener('devicemotion', handler)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "device_motion_keylogging" in types


class TestDataTransmitted:
    def test_accelerometer_sent_warns(self):
        s = _scanner()
        # _DM_SEND_RE: acceleration before fetch within 200 non-semicolon chars
        body = "window.addEventListener('devicemotion', e => { const a = e.acceleration\nfetch('/log', {body: JSON.stringify(a)}) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "device_motion_data_transmitted" in types


class TestNoPermissionRequest:
    def test_no_request_permission_warns(self):
        s = _scanner()
        body = "window.addEventListener('devicemotion', handler)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "device_motion_no_permission_request" in types

    def test_with_request_permission_passes(self):
        s = _scanner()
        body = "DeviceMotionEvent.requestPermission().then(() => { window.addEventListener('devicemotion', handler) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "device_motion_no_permission_request" not in types


class TestNotUsed:
    def test_no_device_motion_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "device_motion_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
