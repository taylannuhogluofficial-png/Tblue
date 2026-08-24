"""Extra branch coverage for tblue.scanner.http_methods."""

from unittest.mock import MagicMock, patch
from tblue.scanner.http_methods import HTTPMethodsScanner

URL = "https://example.com"
API_URL = "https://example.com/api/v1/users"


def _scanner():
    session = MagicMock()
    return HTTPMethodsScanner(session)


def _resp(status=200, allow_header="", extra_headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = ""
    headers = {}
    if allow_header:
        headers["allow"] = allow_header
    if extra_headers:
        headers.update(extra_headers)
    r.headers = headers
    return r


def test_no_response_returns_empty():
    """Branch: http.options returns None → empty results."""
    s = _scanner()
    s.http.options = MagicMock(return_value=None)
    results = s.scan(URL)
    assert results == []


def test_status_405_no_allow_gets_pass():
    """Branch: 405 response without Allow header → PASS."""
    s = _scanner()
    s.http.options = MagicMock(return_value=_resp(405, ""))
    results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_trace_method_enabled_is_fail():
    """Branch: TRACE in Allow header → FAIL."""
    s = _scanner()
    s.http.options = MagicMock(return_value=_resp(200, "GET, POST, TRACE"))
    results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_put_on_api_path_is_not_flagged():
    """Branch: PUT on /api/ path → not flagged (API paths are exempt)."""
    s = _scanner()
    s.http.options = MagicMock(return_value=_resp(200, "GET, POST, PUT, DELETE"))
    results = s.scan(API_URL)
    write_fails = [r for r in results if "PUT" in r.get("type", "") or "DELETE" in r.get("type", "")]
    assert not write_fails


def test_put_on_non_api_path_is_warn():
    """Branch: PUT on non-API path → WARN."""
    s = _scanner()
    s.http.options = MagicMock(return_value=_resp(200, "GET, POST, PUT"))
    results = s.scan("https://example.com/about")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_unexpected_status_returns_empty():
    """Branch: OPTIONS returns unexpected status (e.g. 500) → empty results."""
    s = _scanner()
    s.http.options = MagicMock(return_value=_resp(500, ""))
    results = s.scan(URL)
    assert results == []
