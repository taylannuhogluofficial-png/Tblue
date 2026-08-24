"""Tests for JSONSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.json_security import JSONSecurityScanner


def _scanner():
    s = JSONSecurityScanner.__new__(JSONSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_json_parse_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const data = JSON.parse(searchParams.get('config'))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "json_parse_from_param" in types


def test_json_stringify_credentials_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const payload = JSON.stringify({token: authToken, secret: apiKey})\n"
        "fetch('/collect', {body: payload})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "json_stringify_credentials_exfil" in types


def test_json_parse_result_evaled():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const code = JSON.parse(response)\n"
        "eval(code.script)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "json_parse_result_evaled" in types


def test_json_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No data serialization here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "json_not_used"
    assert results[0]["status"] == "PASS"


def test_json_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "json_not_used"
