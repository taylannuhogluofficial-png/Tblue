"""Tests for ContentTypeSniffingScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.content_type_sniffing import ContentTypeSniffingScanner


def _scanner():
    s = ContentTypeSniffingScanner.__new__(ContentTypeSniffingScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestRiskyMIMENoSniff:
    def test_text_plain_no_nosniff_warns(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "some text content", {
            "content-type": "text/plain",
        })
        results = s.scan("http://example.com/file.txt")
        types = [r["type"] for r in results]
        assert "content_sniffing_risky_mime_no_nosniff" in types

    def test_svg_no_nosniff_warns(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<svg>...</svg>", {
            "content-type": "image/svg+xml",
        })
        results = s.scan("http://example.com/image.svg")
        types = [r["type"] for r in results]
        assert "content_sniffing_risky_mime_no_nosniff" in types

    def test_octet_stream_no_nosniff_warns(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "binary content", {
            "content-type": "application/octet-stream",
        })
        results = s.scan("http://example.com/file.bin")
        types = [r["type"] for r in results]
        assert "content_sniffing_risky_mime_no_nosniff" in types


class TestNoSniffPresent:
    def test_nosniff_header_present_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "some text", {
            "content-type": "text/plain",
            "x-content-type-options": "nosniff",
        })
        results = s.scan("http://example.com/file.txt")
        types = [r["type"] for r in results]
        assert "content_sniffing_risky_mime_no_nosniff" not in types

    def test_html_without_nosniff_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>page</html>", {
            "content-type": "text/html; charset=utf-8",
        })
        results = s.scan("http://example.com/")
        types = [r["type"] for r in results]
        assert "content_sniffing_risky_mime_no_nosniff" not in types
        assert "content_sniffing_nosniff_missing" not in types


class TestJSONWithHTML:
    def test_json_with_html_no_nosniff_warns(self):
        s = _scanner()
        json_with_html = '{"message": "<script>alert(1)</script>", "data": "test"}'

        def side_effect(url):
            return _resp(200, json_with_html, {
                "content-type": "application/json",
            })

        s.http.get.side_effect = side_effect
        results = s.scan("http://example.com/api")
        types = [r["type"] for r in results]
        assert "content_sniffing_html_in_json" in types

    def test_json_with_html_with_nosniff_passes(self):
        s = _scanner()
        json_with_html = '{"message": "<img src=x onerror=alert(1)>"}'

        def side_effect(url):
            return _resp(200, json_with_html, {
                "content-type": "application/json",
                "x-content-type-options": "nosniff",
            })

        s.http.get.side_effect = side_effect
        results = s.scan("http://example.com/api")
        types = [r["type"] for r in results]
        assert "content_sniffing_html_in_json" not in types


class TestUploadEndpoint:
    def test_upload_endpoint_no_nosniff_warns(self):
        s = _scanner()

        def side_effect(url):
            if "/uploads/" in url or "/upload/" in url or "/files/" in url:
                return _resp(200, "file content", {
                    "content-type": "text/plain",
                })
            return _resp(200, "<html>ok</html>", {
                "content-type": "text/html",
            })

        s.http.get.side_effect = side_effect
        results = s.scan("http://example.com/")
        types = [r["type"] for r in results]
        assert "content_sniffing_upload_no_nosniff" in types

    def test_upload_endpoint_with_nosniff_passes(self):
        s = _scanner()

        def side_effect(url):
            if "/uploads/" in url or "/upload/" in url or "/files/" in url:
                return _resp(200, "file content", {
                    "content-type": "text/plain",
                    "x-content-type-options": "nosniff",
                })
            return _resp(200, "<html>ok</html>", {
                "content-type": "text/html",
            })

        s.http.get.side_effect = side_effect
        results = s.scan("http://example.com/")
        types = [r["type"] for r in results]
        assert "content_sniffing_upload_no_nosniff" not in types


class TestCleanScan:
    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
