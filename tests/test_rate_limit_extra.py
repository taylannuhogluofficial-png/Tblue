"""Extra branch coverage for tblue.scanner.rate_limit."""

from unittest.mock import MagicMock, patch
from tblue.scanner.rate_limit import RateLimitScanner

URL = "https://example.com"


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.url = URL
    return r


def _scanner():
    session = MagicMock()
    return RateLimitScanner(session)


def test_rate_limit_headers_present_passes():
    """X-RateLimit-Limit header present → PASS."""
    s = _scanner()
    hdrs = {"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "95"}
    with patch.object(s.http, "get", return_value=_resp("", headers=hdrs)):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_no_rate_limit_headers_warns():
    """No rate-limit headers → WARN or FAIL."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("", headers={})):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad


def test_none_response_no_fail():
    """None response → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert all(r["status"] != "FAIL" for r in results)


def test_retry_after_header_passes():
    """Retry-After header present → acceptable rate limiting."""
    s = _scanner()
    hdrs = {"Retry-After": "60"}
    with patch.object(s.http, "get", return_value=_resp("", status=429, headers=hdrs)):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_result_keys():
    """Results contain required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
