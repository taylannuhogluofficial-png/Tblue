"""Tests for HTTPRequestSmugglingScanner."""
from unittest.mock import MagicMock
from tblue.scanner.http_request_smuggling import HTTPRequestSmugglingScanner


def _scanner():
    s = HTTPRequestSmugglingScanner.__new__(HTTPRequestSmugglingScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_te_cl_conflict():
    s = _scanner()
    s.http.get.return_value = _resp(
        "HTTP/1.1 200 OK",
        headers={"Transfer-Encoding": "chunked", "Content-Length": "5"}
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "http_smuggling_te_cl_conflict" in types


def test_proxy_te_mismatch():
    s = _scanner()
    s.http.get.return_value = _resp(
        "HTTP/1.1 200 OK",
        headers={
            "Via": "1.1 proxy.example.com",
            "Transfer-Encoding": "chunked",
            "X-Forwarded-For": "1.2.3.4",
        }
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "http_smuggling_proxy_te_mismatch" in types


def test_duplicate_content_length():
    s = _scanner()
    s.http.get.return_value = _resp(
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nContent-Length: 4\r\n\r\ntest",
        headers={"Content-Length": "100"}
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "http_smuggling_duplicate_content_length" in types


def test_http_smuggling_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Simple page with no HTTP headers exposed</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "http_smuggling_not_used"
    assert results[0]["status"] == "PASS"


def test_http_smuggling_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "http_smuggling_not_used"
