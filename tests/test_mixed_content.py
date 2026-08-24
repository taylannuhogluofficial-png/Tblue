"""
Tests for mixed content scanner.
"""

import pytest
from unittest.mock import MagicMock
from tblue.scanner.mixed_content import MixedContentScanner


def make_scanner(html: str) -> MixedContentScanner:
    session       = MagicMock()
    resp          = MagicMock()
    resp.text     = html
    resp.url      = "https://example.com"
    session.request.return_value = resp
    return MixedContentScanner(session)


def test_http_script_fails():
    html = '<html><body><script src="http://cdn.example.com/js/app.js"></script></body></html>'
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "FAIL" for r in results)


def test_http_image_fails():
    html = '<html><body><img src="http://example.com/image.png"></body></html>'
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "FAIL" for r in results)


def test_http_stylesheet_fails():
    html = '<html><head><link rel="stylesheet" href="http://example.com/style.css"></head></html>'
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "FAIL" for r in results)


def test_https_resources_pass():
    html = '''<html><body>
      <script src="https://cdn.example.com/app.js"></script>
      <img src="https://example.com/image.png">
      <link href="https://example.com/style.css" rel="stylesheet">
    </body></html>'''
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    assert all(r["status"] != "FAIL" for r in results)


def test_no_resources_passes():
    html = "<html><body><p>Hello world</p></body></html>"
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_http_page_skipped():
    scanner = make_scanner("<html><body></body></html>")
    results = scanner.scan("http://example.com")
    assert results == []


def test_http_iframe_fails():
    html = '<html><body><iframe src="http://example.com/frame"></iframe></body></html>'
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "FAIL" for r in results)


def test_failed_request_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("Timeout")
    scanner = MixedContentScanner(session, retries=1)
    results = scanner.scan("https://example.com")
    assert results == []


def test_result_lists_http_resources():
    html = '<html><body><img src="http://evil.com/track.png"><script src="http://evil.com/bad.js"></script></body></html>'
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    fail = next(r for r in results if r["status"] == "FAIL")
    assert len(fail["fields"]) >= 2


def test_http_in_srcset_fails():
    html = '<html><body><img srcset="http://cdn.example.com/small.jpg 320w, https://cdn.example.com/large.jpg 1280w"></body></html>'
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "FAIL" for r in results)


def test_http_form_action_fails():
    html = '<html><body><form action="http://example.com/submit"><button>Go</button></form></body></html>'
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "FAIL" for r in results)


def test_http_inline_style_fails():
    html = '<html><body><div style="background-image: url(http://evil.com/bg.png)"></div></body></html>'
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "FAIL" for r in results)


def test_http_in_style_tag_fails():
    html = '<html><head><style>body { background: url(http://evil.com/bg.jpg); }</style></head></html>'
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "FAIL" for r in results)


def test_insecure_websocket_in_script_fails():
    html = '<html><body><script>var ws = new WebSocket("ws://evil.com/socket");</script></body></html>'
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "FAIL" for r in results)
