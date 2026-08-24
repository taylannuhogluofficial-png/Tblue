"""Tests for CSSCascadeLayersSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.css_cascade_layers_security import CSSCascadeLayersSecurityScanner


def _scanner():
    s = CSSCascadeLayersSecurityScanner.__new__(CSSCascadeLayersSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_css_cascade_layer_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "sheet.insertRule('@layer ' + searchParams.get('layer') + ' { }')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_cascade_layer_from_param" in types


def test_css_cascade_layer_injected():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.styleSheets[0].insertRule('@layer utilities { .hidden { display: none } }')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_cascade_layer_injected" in types


def test_css_cascade_layer_priority_bypass():
    s = _scanner()
    s.http.get.return_value = _resp(
        "@layer override {\n"
        "  display: none !important\n"
        "  color: red !important token-field auth-bypass\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_cascade_layer_priority_bypass" in types


def test_css_cascade_layers_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No cascade layers</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_cascade_layers_not_used"
    assert results[0]["status"] == "PASS"


def test_css_cascade_layers_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_cascade_layers_not_used"
