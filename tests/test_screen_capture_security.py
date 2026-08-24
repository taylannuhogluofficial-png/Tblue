"""Tests for ScreenCaptureSecurityScanner."""
import pytest
from unittest.mock import MagicMock
from tblue.scanner.screen_capture_security import ScreenCaptureSecurityScanner


def _scanner():
    s = ScreenCaptureSecurityScanner.__new__(ScreenCaptureSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestAutoStart:
    def test_auto_start_fails(self):
        s = _scanner()
        body = """
        document.addEventListener('DOMContentLoaded', async () => {
            const stream = await getDisplayMedia({ video: true });
        });
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "screen_capture_auto_start" in types
        assert any(r["status"] == "FAIL" for r in results)


class TestFullMonitor:
    def test_monitor_capture_warns(self):
        s = _scanner()
        body = """
        const stream = await navigator.mediaDevices.getDisplayMedia({
            video: { displaySurface: 'monitor' }
        });
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "screen_capture_full_monitor" in types


class TestScreenshotTransmitted:
    def test_screenshot_send_warns(self):
        s = _scanner()
        # _SCREENSHOT_SEND_RE matches toDataURL() followed by fetch/sendBeacon without ; between them
        body = (
            "const stream = await getDisplayMedia({ video: true })\n"
            "const dataUrl = canvas.toDataURL()\n"
            "fetch('/upload', dataUrl)\n"
        )
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "screen_capture_screenshot_transmitted" in types


class TestMediaRecorder:
    def test_media_recorder_with_screen_warns(self):
        s = _scanner()
        body = """
        const stream = await getDisplayMedia({ video: true });
        const recorder = new MediaRecorder(stream);
        recorder.start();
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "screen_capture_with_recording" in types


class TestNotUsed:
    def test_no_screen_capture_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "screen_capture_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
