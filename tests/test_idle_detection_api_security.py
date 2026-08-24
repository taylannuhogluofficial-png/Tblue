"""Tests for IdleDetectionAPISecurityScanner."""
import pytest
from unittest.mock import MagicMock
from tblue.scanner.idle_detection_api_security import IdleDetectionAPISecurityScanner


def _scanner():
    s = IdleDetectionAPISecurityScanner.__new__(IdleDetectionAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestIdleStateSent:
    def test_idle_state_transmitted_fails(self):
        s = _scanner()
        body = """
        const detector = new IdleDetector();
        detector.addEventListener('change', () => {
            fetch('/api/activity', {body: JSON.stringify({state: detector.userState})});
        });
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "idle_detection_state_transmitted" in types
        assert any(r["status"] == "FAIL" for r in results)


class TestShortThreshold:
    def test_short_threshold_warns(self):
        s = _scanner()
        body = """
        const detector = new IdleDetector();
        await detector.start({ threshold: 5000 });
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "idle_detection_short_threshold" in types

    def test_valid_threshold_passes(self):
        s = _scanner()
        body = """
        const detector = new IdleDetector();
        await detector.start({ threshold: 60000 });
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "idle_detection_short_threshold" not in types


class TestNoPrivacyNotice:
    def test_permission_without_notice_warns(self):
        s = _scanner()
        body = """
        const perm = await IdleDetector.requestPermission();
        if (perm === 'granted') {
            const detector = new IdleDetector();
        }
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "idle_detection_no_privacy_notice" in types


class TestNotUsed:
    def test_no_idle_detection_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "idle_detection_not_used"
        assert results[0]["status"] == "PASS"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
