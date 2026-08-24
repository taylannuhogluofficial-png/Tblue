"""Tests for VibrationSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.vibration_security import VibrationSecurityScanner


def _scanner():
    s = VibrationSecurityScanner.__new__(VibrationSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_vibration_pattern_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.vibrate(JSON.parse(searchParams.get('pattern')))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "vibration_pattern_from_param" in types


def test_vibration_covert_channel():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.vibrate(encodeAsPattern(authToken))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "vibration_covert_channel" in types


def test_vibration_loop_pattern():
    s = _scanner()
    s.http.get.return_value = _resp(
        "setInterval(() => navigator.vibrate([100, 50, 100]), 1000)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "vibration_loop_pattern" in types


def test_vibration_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No haptic feedback here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "vibration_not_used"
    assert results[0]["status"] == "PASS"


def test_vibration_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "vibration_not_used"
