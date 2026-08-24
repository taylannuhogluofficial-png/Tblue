"""Tests for CSSInjectionPassiveScanner."""
from unittest.mock import MagicMock
from tblue.scanner.css_injection_passive import CSSInjectionPassiveScanner


def _scanner():
    s = CSSInjectionPassiveScanner.__new__(CSSInjectionPassiveScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_css_expression():
    s = _scanner()
    s.http.get.return_value = _resp(
        "<style>body { background: expression(alert(1)) }</style>"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_injection_expression_behavior" in types


def test_css_javascript_url():
    s = _scanner()
    s.http.get.return_value = _resp(
        "<style>a { background: url('javascript:alert(1)') }</style>"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_injection_javascript_url" in types


def test_css_style_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        '<div style="color: ${searchParams.get(colorKey)}">Hello</div>'
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_injection_style_from_param" in types


def test_css_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Regular HTML page without style</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_injection_not_used"
    assert results[0]["status"] == "PASS"


def test_css_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_injection_not_used"
