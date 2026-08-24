"""Tests for CSSTypedOMSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.css_typed_om_security import CSSTypedOMSecurityScanner


def _scanner():
    s = CSSTypedOMSecurityScanner.__new__(CSSTypedOMSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_css_typed_om_value_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.attributeStyleMap.set('width', CSS.px(searchParams.get('w')))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_typed_om_value_from_param" in types


def test_css_typed_om_computed_style_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const styleMap = el.computedStyleMap()\n"
        "const vals = {}\n"
        "styleMap.forEach((v, k) => vals[k] = v.toString())\n"
        "fetch('/styles', {body: JSON.stringify(vals)})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_typed_om_computed_style_exfil" in types


def test_css_typed_om_fingerprinting():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const styleMap = el.computedStyleMap()\n"
        "const dpi = styleMap.get('dpi')\n"
        "sendBeacon('/fp', JSON.stringify({devicePixelRatio: dpi, platform: navigator.platform}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_typed_om_fingerprinting" in types


def test_css_typed_om_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No typed style map API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_typed_om_not_used"
    assert results[0]["status"] == "PASS"


def test_css_typed_om_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_typed_om_not_used"
