"""Tests for CSSMasonrySecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.css_masonry_security import CSSMasonrySecurityScanner


def _scanner():
    s = CSSMasonrySecurityScanner.__new__(CSSMasonrySecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_css_masonry_injected_via_dom():
    s = _scanner()
    s.http.get.return_value = _resp(
        "sheet.insertRule('.grid { grid-template-rows: masonry }')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_masonry_injected_via_dom" in types


def test_css_masonry_from_url_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.style['grid-template-rows'] = searchParams.get('layout') === 'masonry' ? 'masonry' : 'auto'"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_masonry_from_url_param" in types


def test_css_masonry_state_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const flow = el.style.masonryAutoFlow\n"
        "sendBeacon('/track', JSON.stringify({flow}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_masonry_state_exfiltrated" in types


def test_css_masonry_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No grid layout features</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_masonry_not_used"
    assert results[0]["status"] == "PASS"


def test_css_masonry_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_masonry_not_used"
