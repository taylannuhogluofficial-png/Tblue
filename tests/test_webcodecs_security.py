"""Tests for WebCodecsSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.webcodecs_security import WebCodecsSecurityScanner


def _scanner():
    s = WebCodecsSecurityScanner.__new__(WebCodecsSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestEncodedDataSent:
    def test_encoder_data_transmitted_warns(self):
        s = _scanner()
        # _WC_ENCODE_SEND_RE: VideoEncoder ... sendBeacon within 300 non-semicolon chars
        body = "const enc = new VideoEncoder({output: chunk => sendBeacon('/upload', chunk), error: e => {}})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "webcodecs_encoded_data_transmitted" in types


class TestDecodeFromURLParam:
    def test_decode_from_url_param_fails(self):
        s = _scanner()
        # _WC_DECODE_URL_PARAM_RE: VideoDecoder ... searchParams within 300 non-semicolon chars
        body = "const dec = new VideoDecoder({output: f => {}, error: e => {}})\nconst src = searchParams.get('stream')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "webcodecs_decode_from_url_param" in types


class TestTimingSideChannel:
    def test_decode_timing_warns(self):
        s = _scanner()
        body = "const dec = new VideoDecoder({output: f => {}, error: e => {}})\nconst t = performance.now()"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "webcodecs_timing_side_channel" in types


class TestNotUsed:
    def test_no_webcodecs_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "webcodecs_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
