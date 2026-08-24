"""Tests for FocusManagementSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.focus_management_security import FocusManagementSecurityScanner


def _scanner():
    s = FocusManagementSecurityScanner.__new__(FocusManagementSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_focus_auto_set_on_sensitive_field():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const element = document.querySelector('#hidden-input')\n"
        "element.focus()\n"
        "// auto-focuses credential and password entry field"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "focus_auto_set_on_sensitive_field" in types


def test_active_element_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const active = document.activeElement\n"
        "sendBeacon('/track', JSON.stringify({focused: active.id}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "active_element_exfiltrated" in types


def test_tabindex_from_url_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.tabIndex = searchParams.get('order')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "tabindex_from_url_param" in types


def test_focus_management_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No keyboard navigation API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "focus_management_not_used"
    assert results[0]["status"] == "PASS"


def test_focus_management_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "focus_management_not_used"
