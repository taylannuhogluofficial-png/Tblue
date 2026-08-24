"""Tests for LaunchHandlerSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.launch_handler_security import LaunchHandlerSecurityScanner


def _scanner():
    s = LaunchHandlerSecurityScanner.__new__(LaunchHandlerSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestOpenRedirect:
    def test_launch_url_open_redirect_fails(self):
        s = _scanner()
        # _LH_REDIRECT_RE: launchQueue ... targetURL (before) ... location.href = (after)
        body = "launchQueue.setConsumer(params => { const url = params.targetURL\nlocation.href = url })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "launch_handler_open_redirect" in types


class TestXSSSink:
    def test_launch_url_to_innerhtml_fails(self):
        s = _scanner()
        # _LH_XSS_SINK_RE: launchQueue ... targetURL (before) ... innerHTML (after)
        body = "launchQueue.setConsumer(p => { const url = p.targetURL\nel.innerHTML = url })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "launch_handler_xss_sink" in types


class TestURLExfil:
    def test_launch_url_exfiltrated_warns(self):
        s = _scanner()
        # _LH_URL_EXFIL_RE: launchQueue ... targetURL (before) ... analytics (after)
        body = "launchQueue.setConsumer(p => { const url = p.targetURL\nanalytics('launch', {url}) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "launch_handler_url_exfiltrated" in types


class TestNotUsed:
    def test_no_launch_handler_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "launch_handler_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
