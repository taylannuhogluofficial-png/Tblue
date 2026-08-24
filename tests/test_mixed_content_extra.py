"""Extra branch coverage for tblue.scanner.mixed_content."""

from unittest.mock import MagicMock
from tblue.scanner.mixed_content import MixedContentScanner

HTTPS_URL = "https://example.com"
HTTP_URL = "http://example.com"


def _scanner(html="", status=200, headers=None):
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = status
    resp.text = html
    resp.headers = headers or {}
    resp.url = HTTPS_URL
    s = MixedContentScanner(session)
    s.http.get = MagicMock(return_value=resp)
    return s


def test_http_url_skipped_immediately():
    """HTTP (non-HTTPS) pages are skipped with no results."""
    s = MixedContentScanner(MagicMock())
    s.http.get = MagicMock(return_value=None)
    results = s.scan(HTTP_URL)
    assert isinstance(results, list)
    assert results == []


def test_no_response_returns_empty():
    """None HTTP response returns an empty list."""
    s = MixedContentScanner(MagicMock())
    s.http.get = MagicMock(return_value=None)
    results = s.scan(HTTPS_URL)
    assert isinstance(results, list)
    assert results == []


def test_http_script_src_flagged():
    """An HTTP script src on an HTTPS page is flagged as mixed content."""
    html = '<html><body><script src="http://cdn.evil.com/lib.js"></script></body></html>'
    s = _scanner(html=html)
    results = s.scan(HTTPS_URL)
    assert isinstance(results, list)
    assert len(results) >= 1
    statuses = [r["status"] for r in results]
    assert "FAIL" in statuses or "WARN" in statuses


def test_no_mixed_content_returns_pass():
    """Page with only HTTPS resources returns a PASS result."""
    html = '<html><body><script src="https://cdn.example.com/lib.js"></script></body></html>'
    s = _scanner(html=html)
    results = s.scan(HTTPS_URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "PASS" in statuses


def test_http_img_src_flagged():
    """An HTTP img src on an HTTPS page is detected as mixed content."""
    html = '<html><body><img src="http://images.example.com/photo.jpg" /></body></html>'
    s = _scanner(html=html)
    results = s.scan(HTTPS_URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "FAIL" in statuses or "WARN" in statuses


def test_http_form_action_flagged():
    """An HTTP form action on an HTTPS page is flagged."""
    html = '<html><body><form action="http://example.com/submit"><input type="submit"/></form></body></html>'
    s = _scanner(html=html)
    results = s.scan(HTTPS_URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "FAIL" in statuses or "WARN" in statuses
