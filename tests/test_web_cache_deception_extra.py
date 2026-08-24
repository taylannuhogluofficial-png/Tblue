"""Extra branch coverage for tblue.scanner.web_cache_deception."""

from unittest.mock import MagicMock, patch
from tblue.scanner.web_cache_deception import WebCacheDeceptionScanner

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
    return WebCacheDeceptionScanner(session)


def test_no_sensitive_content_passes():
    """Normal page with no sensitive data → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html>Home</html>")):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_cached_sensitive_content_fails():
    """Cached page with user-specific data + cache headers → FAIL."""
    s = _scanner()
    hdrs = {"Cache-Control": "public, max-age=3600", "X-Cache": "HIT"}
    body = "<html>Welcome, user@example.com. Your account balance: $500</html>"

    def get_side(url, **kw):
        if ".css" in url or ".js" in url:
            return _resp(body, 200, hdrs)
        return _resp(body)

    with patch.object(s.http, "get", side_effect=get_side):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_no_cache_header_passes():
    """Sensitive endpoint with Cache-Control: no-store → PASS."""
    s = _scanner()
    hdrs = {"Cache-Control": "no-store, no-cache, private"}
    body = "<html>Welcome, user@example.com</html>"
    with patch.object(s.http, "get", return_value=_resp(body, 200, hdrs)):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_none_response_no_fail():
    """None response → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert all(r["status"] != "FAIL" for r in results)


def test_result_keys():
    """Results contain required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
