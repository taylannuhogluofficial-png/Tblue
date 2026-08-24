"""Tests for CSSNestingSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.css_nesting_security import CSSNestingSecurityScanner


def _scanner():
    s = CSSNestingSecurityScanner.__new__(CSSNestingSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_css_nesting_injected_via_dom():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.innerHTML = '<style>.parent { & .child { color: blue } }</style>'"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_nesting_injected_via_dom" in types


def test_css_nesting_url_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        ".parent {\n"
        "  color: blue\n"
        "  & .tracker { content: url('https://evil.com/track') }\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_nesting_url_exfil" in types


def test_css_nesting_rule_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "sheet.insertRule('@nest ' + searchParams.get('selector') + ' { color: red }')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_nesting_rule_from_param" in types


def test_css_nesting_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No CSS nesting</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_nesting_not_used"
    assert results[0]["status"] == "PASS"


def test_css_nesting_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_nesting_not_used"
