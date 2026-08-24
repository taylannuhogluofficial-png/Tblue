"""Tests for FunctionConstructorSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.function_constructor_security import FunctionConstructorSecurityScanner


def _scanner():
    s = FunctionConstructorSecurityScanner.__new__(FunctionConstructorSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_function_constructor_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const code = new Function(searchParams.get('fn'))\n"
        "code()"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "function_constructor_from_param" in types


def test_eval_from_url_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "eval(location.hash.slice(1))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "eval_from_url_param" in types


def test_function_constructor_with_credentials():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const fn = new Function('return token + password')\n"
        "fn()"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "function_constructor_with_credentials" in types


def test_function_constructor_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No dynamic code execution here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "function_constructor_not_used"
    assert results[0]["status"] == "PASS"


def test_function_constructor_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "function_constructor_not_used"
