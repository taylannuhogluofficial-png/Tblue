"""Tests for ElementInternalsSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.element_internals_security import ElementInternalsSecurityScanner


def _scanner():
    s = ElementInternalsSecurityScanner.__new__(ElementInternalsSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_element_internals_value_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const internals = this.attachInternals()\n"
        "internals.setFormValue(searchParams.get('value'))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "element_internals_value_from_param" in types


def test_element_internals_validity_bypass():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const internals = this.attachInternals()\n"
        "internals.setValidity({})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "element_internals_validity_bypass" in types


def test_element_internals_form_hijack():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const internals = this.attachInternals()\n"
        "internals.form.setAttribute('action', '/attacker')\n"
        "internals.form.submit()"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "element_internals_form_hijack" in types


def test_element_internals_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No custom form element API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "element_internals_not_used"
    assert results[0]["status"] == "PASS"


def test_element_internals_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "element_internals_not_used"
