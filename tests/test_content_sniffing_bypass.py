"""Tests for ContentSniffingBypassScanner."""
from unittest.mock import MagicMock
from tblue.scanner.content_sniffing_bypass import ContentSniffingBypassScanner


def _scanner():
    s = ContentSniffingBypassScanner.__new__(ContentSniffingBypassScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_nosniff_missing_for_html():
    s = _scanner()
    s.http.get.return_value = _resp(
        "<html><body>Hello</body></html>",
        headers={"Content-Type": "text/html; charset=utf-8"},
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "content_sniffing_nosniff_missing" in types


def test_script_in_octet_stream():
    s = _scanner()
    s.http.get.return_value = _resp(
        "<html><script>alert(1)</script></html>",
        headers={"Content-Type": "application/octet-stream"},
    )
    results = s.scan("http://example.com/file")
    types = [r["type"] for r in results]
    assert "content_sniffing_script_in_octet_stream" in types


def test_upload_filename_reflected():
    s = _scanner()
    s.http.get.return_value = _resp(
        'File uploaded successfully. name="malicious.html" saved.',
        headers={"Content-Type": "text/html"},
    )
    results = s.scan("http://example.com/upload")
    types = [r["type"] for r in results]
    assert "content_sniffing_upload_filename_reflected" in types


def test_svg_no_nosniff():
    s = _scanner()
    s.http.get.return_value = _resp(
        '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
        headers={"Content-Type": "image/svg+xml"},
    )
    results = s.scan("http://example.com/image.svg")
    types = [r["type"] for r in results]
    assert "content_sniffing_svg_no_nosniff" in types


def test_content_sniffing_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("No relevant content here")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "content_sniffing_bypass_not_used"
    assert results[0]["status"] == "PASS"
