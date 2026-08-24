"""Tests for SQLInjectionClientSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.sql_injection_client_security import SQLInjectionClientSecurityScanner


def _scanner():
    s = SQLInjectionClientSecurityScanner.__new__(SQLInjectionClientSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_sql_injection_query_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "db.executeSql('SELECT * FROM items WHERE name = ' + searchParams.get('filter'))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "sql_injection_query_from_param" in types


def test_sql_injection_string_concat():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const query = 'SELECT * FROM users WHERE id = ' + userInput"
        "db.executeSql(query)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "sql_injection_string_concat" in types


def test_sql_injection_result_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "db.executeSql('SELECT * FROM secrets', [], results => {"
        "  sendBeacon('/exfil', JSON.stringify(results.rows))"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "sql_injection_result_exfil" in types


def test_sql_injection_client_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No database query code here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "sql_injection_client_not_used"
    assert results[0]["status"] == "PASS"


def test_sql_injection_client_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "sql_injection_client_not_used"
