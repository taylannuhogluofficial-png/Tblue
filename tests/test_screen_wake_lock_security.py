"""Tests for ScreenWakeLockSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.screen_wake_lock_security import ScreenWakeLockSecurityScanner


def _scanner():
    s = ScreenWakeLockSecurityScanner.__new__(ScreenWakeLockSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestAutoAcquire:
    def test_wake_lock_on_load_warns(self):
        s = _scanner()
        body = "window.addEventListener('load', async () => { const lock = await navigator.wakeLock.request('screen') })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "screen_wake_lock_auto_acquire" in types


class TestNeverReleased:
    def test_no_release_warns(self):
        s = _scanner()
        body = "const lock = await navigator.wakeLock.request('screen')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "screen_wake_lock_never_released" in types

    def test_with_release_passes(self):
        s = _scanner()
        body = "const lock = await navigator.wakeLock.request('screen'); document.addEventListener('visibilitychange', () => lock.release())"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "screen_wake_lock_never_released" not in types


class TestNoVisibilityHandler:
    def test_no_visibility_change_warns(self):
        s = _scanner()
        body = "const lock = await navigator.wakeLock.request('screen')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "screen_wake_lock_no_visibility_handler" in types


class TestNotUsed:
    def test_no_wake_lock_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "screen_wake_lock_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
