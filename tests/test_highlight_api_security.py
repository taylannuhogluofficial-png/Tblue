"""Tests for HighlightAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.highlight_api_security import HighlightAPISecurityScanner


def _scanner():
    s = HighlightAPISecurityScanner.__new__(HighlightAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_highlight_range_from_url_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const h = new Highlight(range)\n"
        "CSS.highlights.set('search', h)\n"
        "// range derived from searchParams.get('q')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "highlight_range_from_url_param" in types


def test_highlight_sensitive_text():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const h = new Highlight(sensitiveRange)\n"
        "CSS.highlights.set('highlight-password', h)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "highlight_sensitive_text" in types


def test_highlight_state_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const h = new Highlight(selectedRange)\n"
        "CSS.highlights.set('active', h)\n"
        "sendBeacon('/track', JSON.stringify({highlighted: h.size}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "highlight_state_exfiltrated" in types


def test_highlight_api_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No custom text marker API used</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "highlight_api_not_used"
    assert results[0]["status"] == "PASS"


def test_highlight_api_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "highlight_api_not_used"
