"""
Tests for HTTP method enumeration scanner.
"""

import pytest
from unittest.mock import MagicMock
from tblue.scanner.http_methods import HTTPMethodsScanner


def make_scanner(allow_header: str = "", status_code: int = 200) -> HTTPMethodsScanner:
    session = MagicMock()
    resp    = MagicMock()
    resp.status_code = status_code
    resp.headers     = {"allow": allow_header} if allow_header else {}
    resp.url         = "https://example.com"
    session.request.return_value = resp
    return HTTPMethodsScanner(session)


def test_trace_enabled_fails():
    scanner = make_scanner("GET, POST, HEAD, TRACE")
    results = scanner.scan("https://example.com")
    assert any("trace" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_connect_enabled_fails():
    scanner = make_scanner("GET, POST, CONNECT")
    results = scanner.scan("https://example.com")
    assert any("connect" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_safe_methods_only_passes():
    scanner = make_scanner("GET, POST, HEAD, OPTIONS")
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] == "FAIL" for r in results)


def test_put_on_non_api_warns():
    scanner = make_scanner("GET, POST, PUT, DELETE")
    results = scanner.scan("https://example.com/page")
    assert any("write method" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_put_on_api_path_not_flagged():
    session = MagicMock()
    resp    = MagicMock()
    resp.status_code = 200
    resp.headers     = {"allow": "GET, POST, PUT, DELETE, PATCH"}
    resp.url         = "https://example.com/api/v1/users"
    session.request.return_value = resp
    scanner = HTTPMethodsScanner(session)
    results = scanner.scan("https://example.com/api/v1/users")
    write_warns = [r for r in results if "write method" in r["type"].lower() and r["status"] == "WARN"]
    assert len(write_warns) == 0


def test_no_allow_header_passes():
    scanner = make_scanner(allow_header="", status_code=200)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_404_response_returns_empty():
    scanner = make_scanner(allow_header="", status_code=404)
    results = scanner.scan("https://example.com")
    assert results == []


def test_failed_request_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("Timeout")
    scanner = HTTPMethodsScanner(session, retries=1)
    results = scanner.scan("https://example.com")
    assert results == []
