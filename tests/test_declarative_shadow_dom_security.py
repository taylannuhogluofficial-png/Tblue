"""Tests for DeclarativeShadowDOMSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.declarative_shadow_dom_security import DeclarativeShadowDOMSecurityScanner


def _scanner():
    s = DeclarativeShadowDOMSecurityScanner.__new__(DeclarativeShadowDOMSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_declarative_shadow_dom_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.setHTMLUnsafe(searchParams.get('template'))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "declarative_shadow_dom_from_param" in types


def test_set_html_unsafe_with_user_input():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const raw = document.getElementById('editor').innerHTML\n"
        "host.setHTMLUnsafe(innerHTML)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "set_html_unsafe_with_user_input" in types


def test_declarative_shadow_dom_script_injection():
    s = _scanner()
    s.http.get.return_value = _resp(
        "<template shadowrootmode='open'>\n"
        "  <script>fetch('/data', {credentials: 'include'})</script>\n"
        "</template>"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "declarative_shadow_dom_script_injection" in types


def test_declarative_shadow_dom_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No shadow root components</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "declarative_shadow_dom_not_used"
    assert results[0]["status"] == "PASS"


def test_declarative_shadow_dom_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "declarative_shadow_dom_not_used"
