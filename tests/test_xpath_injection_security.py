"""Tests for XPathInjectionSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.xpath_injection_security import XPathInjectionSecurityScanner


def _scanner():
    s = XPathInjectionSecurityScanner.__new__(XPathInjectionSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_xpath_injection_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.evaluate(searchParams.get('xpath'), document, null, XPathResult.ANY_TYPE, null)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "xpath_injection_from_param" in types


def test_xpath_result_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const result = document.evaluate('//user/token', xmlDoc, null, XPathResult.STRING_TYPE, null)"
        "sendBeacon('/collect', result.stringValue)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "xpath_result_exfil" in types


def test_xpath_boolean_injection_pattern():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.evaluate(\"//user[name/text()='admin' or '1'='1']\","
        "  xmlDoc, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "xpath_boolean_injection_pattern" in types


def test_xpath_injection_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No XML document traversal here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "xpath_injection_not_used"
    assert results[0]["status"] == "PASS"


def test_xpath_injection_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "xpath_injection_not_used"
