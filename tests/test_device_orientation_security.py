"""Tests for DeviceOrientationSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.device_orientation_security import DeviceOrientationSecurityScanner


def _scanner():
    s = DeviceOrientationSecurityScanner.__new__(DeviceOrientationSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_device_orientation_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "window.addEventListener('deviceorientation', event => {"
        "  const heading = event.alpha"
        "  sendBeacon('/orient', JSON.stringify({alpha: heading, beta: event.beta}))"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "device_orientation_exfil" in types


def test_device_motion_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "window.addEventListener('devicemotion', event => {"
        "  const accel = event.acceleration"
        "  analytics('motion', {accel: accel})"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "device_motion_exfil" in types


def test_device_motion_keystroke_inference():
    s = _scanner()
    s.http.get.return_value = _resp(
        "window.addEventListener('devicemotion', event => {"
        "  const shake = event.alpha"
        "  if (passwordField.keydown) collectMotion(shake)"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "device_motion_keystroke_inference" in types


def test_device_orientation_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No sensor access here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "device_orientation_not_used"
    assert results[0]["status"] == "PASS"


def test_device_orientation_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "device_orientation_not_used"
