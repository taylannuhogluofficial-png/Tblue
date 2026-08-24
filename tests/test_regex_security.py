"""Tests for RegexSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.regex_security import RegexSecurityScanner


def _scanner():
    s = RegexSecurityScanner.__new__(RegexSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_regex_from_url_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const re = new RegExp(searchParams.get('pattern'))\n"
        "re.test(input)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "regex_from_url_param" in types


def test_regex_result_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const match = /secret/.exec(document.body.innerHTML)\n"
        "sendBeacon('/log', JSON.stringify(match))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "regex_result_exfil" in types


def test_regex_injection_via_eval():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const pattern = userInput\n"
        "const re = new RegExp(pattern)\n"
        "eval(re.exec(data)[0])"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "regex_injection_via_eval" in types


def test_regex_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No pattern matching here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "regex_not_used"
    assert results[0]["status"] == "PASS"


def test_regex_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "regex_not_used"
