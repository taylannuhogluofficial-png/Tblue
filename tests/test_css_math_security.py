"""Tests for CSSMathSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.css_math_security import CSSMathSecurityScanner


def _scanner():
    s = CSSMathSecurityScanner.__new__(CSSMathSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_css_math_from_url_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.style.width = 'calc(' + searchParams.get('w') + 'px)'"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_math_from_url_param" in types


def test_css_math_env_fingerprinting():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const w = getComputedStyle(el).getPropertyValue('width')\n"
        "const safeArea = env(safe-area-inset-top)\n"
        "sendBeacon('/fp', JSON.stringify({safeArea}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_math_env_fingerprinting" in types


def test_css_math_injected_via_dom():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.setAttribute('style', 'margin: calc(100% - 20px)')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_math_injected_via_dom" in types


def test_css_math_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No CSS math</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_math_not_used"
    assert results[0]["status"] == "PASS"


def test_css_math_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_math_not_used"
