"""Tests for CompressionStreamsSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.compression_streams_security import CompressionStreamsSecurityScanner


def _scanner():
    s = CompressionStreamsSecurityScanner.__new__(CompressionStreamsSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestBreachPattern:
    def test_secret_mixed_with_input_fails(self):
        s = _scanner()
        # _CS_MIXED_COMPRESS_RE: CompressionStream ... cookie within 400 non-semicolon chars
        body = "const cs = new CompressionStream('gzip')\nconst data = userInput + cookie"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "compression_streams_breach_pattern" in types


class TestDecompressUntrusted:
    def test_decompress_from_url_fails(self):
        s = _scanner()
        # _CS_DECOMPRESS_URL_RE: DecompressionStream ... fetch within 300 non-semicolon chars
        body = "const ds = new DecompressionStream('deflate')\nconst resp = await fetch(location.search)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "compression_streams_decompress_untrusted" in types


class TestNoSizeLimit:
    def test_no_size_limit_warns(self):
        s = _scanner()
        body = "const ds = new DecompressionStream('deflate'); const reader = ds.readable.getReader()"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "compression_streams_no_size_limit" in types

    def test_with_size_limit_passes(self):
        s = _scanner()
        body = "const ds = new DecompressionStream('deflate'); if (data.byteLength > MAX_SIZE) throw new Error('too large')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "compression_streams_no_size_limit" not in types


class TestNotUsed:
    def test_no_compression_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "compression_streams_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
