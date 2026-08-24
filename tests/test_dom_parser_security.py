"""Tests for DOMParserSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.dom_parser_security import DOMParserSecurityScanner


def _scanner():
    s = DOMParserSecurityScanner.__new__(DOMParserSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_dom_parser_html_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const doc = parser.parseFromString(searchParams.get('content'), 'text/html')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "dom_parser_html_from_param" in types


def test_dom_parser_exfil_serialized():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const xml = new XMLSerializer()\n"
        "const data = xml.serializeToString(document.body)\n"
        "fetch('/exfil', {body: data})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "dom_parser_exfil_serialized" in types


def test_dom_parser_script_in_parsed_html():
    s = _scanner()
    s.http.get.return_value = _resp(
        "parser.parseFromString('<div><script>alert(1)</script></div>', 'text/html')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "dom_parser_script_in_parsed_html" in types


def test_dom_parser_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No DOM parsing operations</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "dom_parser_not_used"
    assert results[0]["status"] == "PASS"


def test_dom_parser_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "dom_parser_not_used"
