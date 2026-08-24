"""Tests for WebLocksSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.web_locks_security import WebLocksSecurityScanner


def _scanner():
    s = WebLocksSecurityScanner.__new__(WebLocksSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestNameFromParam:
    def test_lock_name_from_url_param_fails(self):
        s = _scanner()
        # _WL_NAME_FROM_PARAM_RE: locks.request(searchParams...)
        body = "navigator.locks.request(searchParams.get('resource'), async lock => { doWork() })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_lock_name_from_url_param" in types


class TestQueryExfil:
    def test_lock_state_exfiltrated_warns(self):
        s = _scanner()
        # _WL_QUERY_EXFIL_RE: locks.query() ... sendBeacon
        body = "navigator.locks.query().then(state => sendBeacon('/log', JSON.stringify(state)))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_lock_state_exfiltrated" in types


class TestTimingOracle:
    def test_timing_oracle_warns(self):
        s = _scanner()
        # _WL_TIMING_ORACLE_RE: locks.request ... performance.now ... analytics
        body = "navigator.locks.request('res', async lock => { const t = performance.now()\nanalytics('lock', {t}) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_lock_timing_oracle" in types


class TestNotUsed:
    def test_no_web_locks_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "web_locks_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
