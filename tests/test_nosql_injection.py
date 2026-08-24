"""Tests for tblue.scanner.nosql_injection — NoSQL injection scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.nosql_injection import NoSQLInjectionScanner


def _scanner():
    session = MagicMock()
    return NoSQLInjectionScanner(session)


def _resp(status=200, body=""):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {"content-type": "text/html"}
    r.cookies = {}
    return r


def _404():
    return _resp(status=404, body="")


def test_no_nosql_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html>Hello</html>")):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_mongo_error_in_response():
    s = _scanner()
    body = "<html>MongoError: Cannot connect to server</html>"
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("error message" in r["type"].lower() for r in fails)


def test_mongoose_error_detected():
    s = _scanner()
    body = "<pre>MongooseError: buffering timed out after 10000ms</pre>"
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_duplicate_key_error():
    s = _scanner()
    body = "E11000 duplicate key error collection: test.users"
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_mongodb_operator_in_url():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        # Value contains $where: operator in query string value
        results = s.scan("https://example.com/api?q=$where:this.isAdmin==true")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("URL parameter" in r["type"] for r in fails)


def test_couchdb_exposed():
    s = _scanner()
    couchdb_body = '{"couchdb": "Welcome", "version": "3.3.2"}'

    def side_effect(url, **kw):
        if "/_all_dbs" in url or "/_utils" in url:
            return _resp(200, couchdb_body)
        return _resp(200, "<html></html>")

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("CouchDB" in r["type"] for r in fails)


def test_no_response():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_exception_in_couchdb_probe():
    s = _scanner()
    call_count = 0

    def side_effect(url, **kw):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return _resp(200, "<html></html>")
        raise ConnectionError("refused")

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_mongodb_operator_in_form_field():
    s = _scanner()
    body = '<form action="/search"><input name="q" value="$where=1" /></form>'
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("form field" in r["type"].lower() for r in fails)
