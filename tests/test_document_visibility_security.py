"""Tests for DocumentVisibilitySecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.document_visibility_security import DocumentVisibilitySecurityScanner


def _scanner():
    s = DocumentVisibilitySecurityScanner.__new__(DocumentVisibilitySecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestStateExfil:
    def test_visibility_state_exfiltrated_warns(self):
        s = _scanner()
        # _DV_STATE_EXFIL_RE: visibilitychange ... visibilityState (before) ... sendBeacon (after)
        body = "document.addEventListener('visibilitychange', () => { const state = document.visibilityState\nsendBeacon('/track', state) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "visibility_state_exfiltrated" in types


class TestTimingTrack:
    def test_timing_tracked_warns(self):
        s = _scanner()
        # _DV_TIMING_TRACK_RE: visibilitychange ... performance.now ... analytics
        body = "document.addEventListener('visibilitychange', () => { const t = performance.now()\nanalytics('tab', {time: t}) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "visibility_timing_tracked" in types


class TestPaymentDetect:
    def test_payment_flow_detection_warns(self):
        s = _scanner()
        # _DV_PAYMENT_DETECT_RE: visibilitychange ... payment
        body = "document.addEventListener('visibilitychange', () => { if (document.hidden) { pausePayment() } })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "visibility_payment_flow_detection" in types


class TestNotUsed:
    def test_no_visibility_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "document_visibility_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
