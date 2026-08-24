"""Tests for APIRateLimitHeadersScanner."""
from unittest.mock import MagicMock
from tblue.scanner.api_rate_limit_headers import APIRateLimitHeadersScanner


def _scanner():
    s = APIRateLimitHeadersScanner.__new__(APIRateLimitHeadersScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_api_missing_rate_limit_headers():
    s = _scanner()
    s.http.get.return_value = _resp(headers={"Content-Type": "application/json"})
    results = s.scan("http://example.com/api/v1/users")
    types = [r["type"] for r in results]
    assert "api_rate_limit_headers_missing" in types


def test_api_rate_limit_zero_limit():
    s = _scanner()
    s.http.get.return_value = _resp(headers={
        "X-RateLimit-Limit": "0",
        "X-RateLimit-Remaining": "0",
    })
    results = s.scan("http://example.com/api/v1/users")
    types = [r["type"] for r in results]
    assert "api_rate_limit_zero_limit" in types


def test_api_rate_limit_retry_after_zero():
    s = _scanner()
    s.http.get.return_value = _resp(headers={
        "Retry-After": "0",
        "X-RateLimit-Limit": "100",
    })
    results = s.scan("http://example.com/api/users")
    types = [r["type"] for r in results]
    assert "api_rate_limit_retry_after_zero" in types


def test_api_rate_limit_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Regular page</html>")
    results = s.scan("http://example.com/about")
    assert results[0]["type"] == "api_rate_limit_headers_not_used"
    assert results[0]["status"] == "PASS"


def test_api_rate_limit_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com/api/v1/items")
    assert results[0]["type"] == "api_rate_limit_headers_not_used"
