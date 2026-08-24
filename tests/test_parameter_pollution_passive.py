"""Tests for ParameterPollutionPassiveScanner."""
from unittest.mock import MagicMock
from tblue.scanner.parameter_pollution_passive import ParameterPollutionPassiveScanner


def _scanner():
    s = ParameterPollutionPassiveScanner.__new__(ParameterPollutionPassiveScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_first_value_only():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const role = req.query.role[0]; authorize(role);"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "parameter_pollution_first_value_only" in types


def test_php_array_pollution():
    s = _scanner()
    s.http.get.return_value = _resp(
        "$value = $_GET['token'][0]; validate($value);"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "parameter_pollution_php_array" in types


def test_method_override():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const method = req.query._method || req.method;"
    )
    results = s.scan("http://example.com?_method=DELETE")
    types = [r["type"] for r in results]
    assert "parameter_pollution_method_override" in types


def test_parameter_pollution_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Static page</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "parameter_pollution_not_used"
    assert results[0]["status"] == "PASS"


def test_parameter_pollution_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "parameter_pollution_not_used"
