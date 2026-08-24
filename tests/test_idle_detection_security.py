"""Tests for IdleDetectionSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.idle_detection_security import IdleDetectionSecurityScanner


def _scanner():
    s = IdleDetectionSecurityScanner.__new__(IdleDetectionSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_idle_detection_state_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const detector = new IdleDetector()"
        "detector.addEventListener('change', () => {"
        "  const state = detector.userState"
        "  sendBeacon('/presence', JSON.stringify({state: state}))"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "idle_detection_state_exfil" in types


def test_idle_detection_continuous_monitor():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const detector = new IdleDetector()"
        "await IdleDetector.requestPermission()"
        "detector.addEventListener('change', () => analytics('idle', {d: detector.screenState}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "idle_detection_continuous_monitor" in types


def test_idle_detection_change_event_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const idleDetector = new IdleDetector()"
        "idleDetector.addEventListener('change', e => fetch('/activity', {body: 'changed'}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "idle_detection_change_event_exfil" in types


def test_idle_detection_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No user presence detection here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "idle_detection_not_used"
    assert results[0]["status"] == "PASS"


def test_idle_detection_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "idle_detection_not_used"
