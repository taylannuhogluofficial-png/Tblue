"""Tests for LongTaskObserverSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.longtask_observer_security import LongTaskObserverSecurityScanner


def _scanner():
    s = LongTaskObserverSecurityScanner.__new__(LongTaskObserverSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestTimingExfil:
    def test_longtask_timing_exfiltrated_warns(self):
        s = _scanner()
        # _LT_TIMING_EXFIL_RE: longtask (before) ... duration (before) ... sendBeacon (after)
        body = "const type = 'longtask'\nnew PerformanceObserver(list => { const t = list.getEntries()[0].duration\nsendBeacon('/perf', t) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "longtask_timing_exfiltrated" in types


class TestCryptoOracle:
    def test_crypto_timing_oracle_fails(self):
        s = _scanner()
        # _LT_CRYPTO_ORACLE_RE: longtask (before) ... encrypt (after)
        body = "const type = 'longtask'\nnew PerformanceObserver(l => { if (l.getEntries()[0].duration > 100) { tryNextKey(encrypt) } })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "longtask_crypto_timing_oracle" in types


class TestAttributionExfil:
    def test_attribution_exfiltrated_warns(self):
        s = _scanner()
        # _LT_ATTRIBUTION_EXFIL_RE: longtask (before) ... attribution (before) ... analytics (after)
        body = "const type = 'longtask'\nnew PerformanceObserver(list => { const attr = list.getEntries()[0].attribution\nanalytics('task', {attr}) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "longtask_attribution_exfiltrated" in types


class TestNotUsed:
    def test_no_longtask_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "longtask_observer_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
