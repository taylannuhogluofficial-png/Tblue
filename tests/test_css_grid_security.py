"""Tests for CSSGridSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.css_grid_security import CSSGridSecurityScanner


def _scanner():
    s = CSSGridSecurityScanner.__new__(CSSGridSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_css_grid_template_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.style.cssText = 'grid-template-areas: ' + searchParams.get('layout')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_grid_template_from_param" in types


def test_css_grid_injected_via_dom():
    s = _scanner()
    s.http.get.return_value = _resp(
        "sheet.insertRule('.grid { grid-template-columns: repeat(3, 1fr) }')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_grid_injected_via_dom" in types


def test_css_grid_timing_oracle():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const t = performance.now()\n"
        "el.style.gridTemplateColumns = 'repeat(100, 1fr)'\n"
        "fetch('/log', {body: String(performance.now() - t)})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_grid_timing_oracle" in types


def test_css_grid_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No layout APIs here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_grid_not_used"
    assert results[0]["status"] == "PASS"


def test_css_grid_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_grid_not_used"
