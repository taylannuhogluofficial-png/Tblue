"""Tests for EventSourceSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.eventsource_security import EventSourceSecurityScanner


def _scanner():
    s = EventSourceSecurityScanner.__new__(EventSourceSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestURLFromParam:
    def test_sse_url_from_param_fails(self):
        s = _scanner()
        body = "const sse = new EventSource(searchParams.get('stream'))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "eventsource_url_from_url_param" in types


class TestExternalURL:
    def test_external_sse_url_warns(self):
        s = _scanner()
        body = "const source = new EventSource('https://stream.tracker.io/events')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "eventsource_external_url" in types


class TestDataExfil:
    def test_sse_data_exfiltrated_fails(self):
        s = _scanner()
        body = "const es = new EventSource('/events')\nes.onmessage = e => { const token = e.data\nfetch('/forward', {body: token}) }"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "eventsource_data_exfiltrated" in types


class TestNotUsed:
    def test_no_eventsource_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "eventsource_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
