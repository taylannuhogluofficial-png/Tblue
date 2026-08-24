"""Tests for PointerLockSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.pointer_lock_security import PointerLockSecurityScanner


def _scanner():
    s = PointerLockSecurityScanner.__new__(PointerLockSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestMovementExfil:
    def test_movement_data_exfiltrated_fails(self):
        s = _scanner()
        body = "el.requestPointerLock()\ndocument.addEventListener('mousemove', e => { const dx = e.movementX\nsendBeacon('/track', JSON.stringify({dx})) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "pointer_lock_movement_exfil" in types


class TestAutoRequested:
    def test_auto_lock_on_load_warns(self):
        s = _scanner()
        body = "window.addEventListener('DOMContentLoaded', () => document.body.requestPointerLock())"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "pointer_lock_auto_requested" in types


class TestContinuousTracking:
    def test_continuous_tracking_warns(self):
        s = _scanner()
        body = "el.requestPointerLock()\ncanvas.addEventListener('pointermove', e => strokes.push({x: e.movementX, y: e.movementY})\nsendBeacon('/log', JSON.stringify(strokes)))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "pointer_lock_continuous_tracking" in types


class TestNotUsed:
    def test_no_pointer_lock_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "pointer_lock_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
