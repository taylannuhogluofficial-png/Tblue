"""Tests for CSSScopeSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.css_scope_security import CSSScopeSecurityScanner


def _scanner():
    s = CSSScopeSecurityScanner.__new__(CSSScopeSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_css_scope_injected_via_dom():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.innerHTML = '<style>@scope (.card) { .title { font-size: 2em } }</style>'"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_scope_injected_via_dom" in types


def test_css_constructable_sheet_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const sheet = new CSSStyleSheet()\n"
        "sheet.replaceSync(searchParams.get('css'))\n"
        "document.adoptedStyleSheets = [sheet]"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_constructable_sheet_from_param" in types


def test_css_scope_rule_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "sheet.insertRule('@scope (' + searchParams.get('scope') + ') { .el { color: red } }')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_scope_rule_from_param" in types


def test_css_scope_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No CSS scope</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_scope_not_used"
    assert results[0]["status"] == "PASS"


def test_css_scope_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_scope_not_used"
