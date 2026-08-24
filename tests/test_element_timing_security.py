"""Tests for ElementTimingSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.element_timing_security import ElementTimingSecurityScanner


def _scanner():
    s = ElementTimingSecurityScanner.__new__(ElementTimingSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestTimingExfil:
    def test_render_time_exfiltrated_warns(self):
        s = _scanner()
        # _ET_OBSERVER_EXFIL_RE: PerformanceObserver ... 'element' (before) ... sendBeacon (after)
        body = "new PerformanceObserver(l => {}).observe({type: 'element'})\nsendBeacon('/t', entries[0].renderTime)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "element_timing_observer_exfiltrates" in types


class TestAuthOracle:
    def test_auth_oracle_warns(self):
        s = _scanner()
        # _ET_AUTH_ORACLE_RE: elementtiming (before) ... renderTime (before) ... login (after)
        body = "<img elementtiming='hero' src='/avatar.jpg'>\nconst t = entries[0].renderTime\nif (t > 0) { setLoggedIn(true) }"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "element_timing_auth_oracle" in types


class TestObserverExfil:
    def test_observer_entries_exfiltrated_warns(self):
        s = _scanner()
        # _ET_OBSERVER_EXFIL_RE: PerformanceObserver ... 'element' (before) ... fetch (after)
        body = "new PerformanceObserver(l => {}).observe({entryTypes: ['element']})\nfetch('/log', {body: JSON.stringify(entries)})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "element_timing_observer_exfiltrates" in types


class TestNotUsed:
    def test_no_element_timing_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "element_timing_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
