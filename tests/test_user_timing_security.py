"""Tests for UserTimingSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.user_timing_security import UserTimingSecurityScanner


def _scanner():
    s = UserTimingSecurityScanner.__new__(UserTimingSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestSensitiveMarkNames:
    def test_sensitive_mark_warns(self):
        s = _scanner()
        body = "performance.mark('user-login-complete'); performance.measure('login-duration', 'user-login-start', 'user-login-complete')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "user_timing_sensitive_mark_names" in types


class TestDurationTransmitted:
    def test_duration_sent_warns(self):
        s = _scanner()
        # _UT_DURATION_SEND_RE: duration before fetch within 200 non-semicolon chars
        body = "performance.measure('perf')\nconst dur = entry.duration\nfetch('/metrics', {body: dur})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "user_timing_duration_transmitted" in types


class TestAnalyticsShared:
    def test_timing_to_analytics_fails(self):
        s = _scanner()
        body = "performance.mark('start'); analytics('timing', {duration: performance.now()})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "user_timing_shared_with_analytics" in types


class TestNotUsed:
    def test_no_timing_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "user_timing_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
