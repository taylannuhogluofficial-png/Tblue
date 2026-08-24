"""Tests for FencedFrameSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.fenced_frame_security import FencedFrameSecurityScanner


def _scanner():
    s = FencedFrameSecurityScanner.__new__(FencedFrameSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestURLFromParam:
    def test_url_from_param_fails(self):
        s = _scanner()
        body = "const ff = document.createElement('fencedframe')\nff.config = searchParams.get('url')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "fenced_frame_url_from_param" in types


class TestReportExfil:
    def test_report_sensitive_data_fails(self):
        s = _scanner()
        body = "fence.reportEvent({eventType: 'click', eventData: JSON.stringify({userId: user.email, token: authToken})})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "fenced_frame_report_sensitive_data" in types


class TestParentComm:
    def test_parent_communication_warns(self):
        s = _scanner()
        body = "HTMLFencedFrameElement.prototype.connect = () => fencedframe.postMessage('data', '*')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "fenced_frame_parent_communication_attempt" in types


class TestNotUsed:
    def test_no_fenced_frame_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "fenced_frame_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
