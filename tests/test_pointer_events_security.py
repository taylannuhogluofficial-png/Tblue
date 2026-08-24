"""Tests for PointerEventsSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.pointer_events_security import PointerEventsSecurityScanner


def _scanner():
    s = PointerEventsSecurityScanner.__new__(PointerEventsSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_pointer_movement_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.addEventListener('pointermove', e => {\n"
        "  sendBeacon('/track', JSON.stringify({x: e.clientX, y: e.clientY}))\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "pointer_movement_exfiltrated" in types


def test_pointer_device_fingerprinted():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.addEventListener('pointerdown', e => {\n"
        "  const metrics = {pressure: e.pressure, tiltX: e.tiltX}\n"
        "  analytics('device_fingerprint', metrics)\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "pointer_device_fingerprinted" in types


def test_pointer_capture_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.setPointerCapture(e.pointerId)\n"
        "fetch('/capture', {body: JSON.stringify(coords)})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "pointer_capture_exfil" in types


def test_pointer_events_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No pointer event listeners</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "pointer_events_not_used"
    assert results[0]["status"] == "PASS"


def test_pointer_events_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "pointer_events_not_used"
