"""Extra branch coverage for tblue.scanner.server_timing."""

from unittest.mock import MagicMock, patch
from tblue.scanner.server_timing import ServerTimingScanner

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
    return ServerTimingScanner(session)


def test_db_in_server_timing_fails():
    """Server-Timing header with 'db' metric name → FAIL."""
    s = _scanner()
    # Must use lowercase key since scanner calls headers.get("server-timing", "")
    hdrs = {"server-timing": "db;dur=53.2,app;dur=47.2"}
    with patch.object(s.http, "get", return_value=_resp("", headers=hdrs)):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad


def test_no_server_timing_passes():
    """No Server-Timing header → PASS."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("", headers={})):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_none_response_no_fail():
    """None response → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert all(r["status"] != "FAIL" for r in results)


def test_auth_in_server_timing_fails():
    """Server-Timing exposing auth service name → FAIL."""
    s = _scanner()
    hdrs = {"server-timing": "auth;dur=12.1,total;dur=120"}
    with patch.object(s.http, "get", return_value=_resp("", headers=hdrs)):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad


def test_result_keys():
    """Results contain required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
