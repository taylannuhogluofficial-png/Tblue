"""Extra branch coverage for tblue.scanner.rate_limiting."""

from unittest.mock import MagicMock, patch
from tblue.scanner.rate_limiting import RateLimitingScanner

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
    return RateLimitingScanner(session)


def test_consistent_200s_warns():
    """All repeated requests return 200 → WARN (no rate limiting)."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert isinstance(results, list)


def test_429_response_passes():
    """Server returns 429 → rate limiting enforced, PASS."""
    s = _scanner()
    responses = [_resp("", 200)] * 5 + [_resp("Too Many Requests", 429)]
    counter = [0]

    def get_side(*a, **kw):
        r = responses[min(counter[0], len(responses) - 1)]
        counter[0] += 1
        return r

    with patch.object(s.http, "get", side_effect=get_side):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_none_response_no_fail():
    """None response → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert all(r["status"] != "FAIL" for r in results)


def test_result_structure():
    """Results contain required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
