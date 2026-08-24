"""Tests for NoSQLInjectionAdvancedScanner."""
from unittest.mock import MagicMock
from tblue.scanner.nosql_injection_advanced import NoSQLInjectionAdvancedScanner


def _scanner():
    s = NoSQLInjectionAdvancedScanner.__new__(NoSQLInjectionAdvancedScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_operator_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const result = users.find({user: req.body.username, role: {$ne: 'guest'}});"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "nosql_injection_operator_from_param" in types


def test_find_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "db.collection('users').find(req.body);"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "nosql_injection_find_from_param" in types


def test_error_disclosure():
    s = _scanner()
    s.http.get.return_value = _resp(
        "MongoError: invalid query: field 'password' does not match schema"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "nosql_injection_error_disclosure" in types


def test_nosql_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Regular page with no database queries</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "nosql_injection_advanced_not_used"
    assert results[0]["status"] == "PASS"


def test_nosql_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "nosql_injection_advanced_not_used"
