"""Tests for CSSCounterSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.css_counter_security import CSSCounterSecurityScanner


def _scanner():
    s = CSSCounterSecurityScanner.__new__(CSSCounterSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_css_counter_injected_via_dom():
    s = _scanner()
    s.http.get.return_value = _resp(
        "sheet.insertRule('body { counter-reset: section 0 }')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_counter_injected_via_dom" in types


def test_css_counter_sensitive_data():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.style.cssText = 'counter-reset: password-attempts 0'\n"
        "el.style.cssText += 'counter-increment: auth-failures'"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_counter_sensitive_data" in types


def test_css_counter_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.style.cssText = 'counter-reset: ' + searchParams.get('count')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_counter_from_param" in types


def test_css_counter_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No CSS numbering or counting</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_counter_not_used"
    assert results[0]["status"] == "PASS"


def test_css_counter_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_counter_not_used"
