"""Tests for CSSHoudiniSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.css_houdini_security import CSSHoudiniSecurityScanner


def _scanner():
    s = CSSHoudiniSecurityScanner.__new__(CSSHoudiniSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_css_houdini_worklet_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const src = searchParams.get('worklet')\n"
        "CSS.paintWorklet.addModule(decodeURIComponent(src))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_houdini_worklet_from_param" in types


def test_css_houdini_external_worklet():
    s = _scanner()
    s.http.get.return_value = _resp(
        "CSS.paintWorklet.addModule('https://cdn.evil.com/painter.js')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_houdini_external_worklet" in types


def test_css_houdini_property_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "CSS.registerProperty({\n"
        "  name: '--' + searchParams.get('prop'),\n"
        "  syntax: '<color>',\n"
        "  inherits: false\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_houdini_property_from_param" in types


def test_css_houdini_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No CSS worklet features used</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_houdini_not_used"
    assert results[0]["status"] == "PASS"


def test_css_houdini_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_houdini_not_used"
