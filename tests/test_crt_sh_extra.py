"""Extra coverage for crt_sh — lines 32 (import path), 79-81 (non-200 from crt.sh)."""

from unittest.mock import MagicMock, patch
from tblue.scanner.crt_sh import CRTShScanner

URL = "https://example.com"


def _make_scanner():
    return CRTShScanner(MagicMock())


def _resp(status=200, body=None, json_data=None, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body or ""
    r.headers = headers or {}
    if json_data is not None:
        r.json.return_value = json_data
    else:
        r.json.side_effect = Exception("no json")
    return r


def test_crt_sh_non_200_returns_no_results():
    """When crt.sh returns a non-200 status, scanner silently returns empty (lines 79-81)."""
    s = _make_scanner()

    # The scanner makes one request to crt.sh; return 500
    with patch.object(s.http, "get", return_value=_resp(status=500)):
        results = s.scan(URL)

    # Non-200 from crt.sh → _query_crt_sh returns None → scanner returns []
    assert results == [], f"Expected empty results on crt.sh 500, got: {results}"


def test_crt_sh_rate_limit_503_returns_empty():
    """crt.sh 503 (rate limited) also returns empty — covers debug log + return None path."""
    s = _make_scanner()

    with patch.object(s.http, "get", return_value=_resp(status=503)):
        results = s.scan(URL)

    assert results == []


def test_crt_sh_network_failure_returns_empty():
    """Network error reaching crt.sh returns empty (exception path in _query_crt_sh)."""
    s = _make_scanner()

    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)

    assert results == []


def test_crt_sh_invalid_hostname_returns_empty():
    """URL with no extractable domain returns immediately without querying crt.sh."""
    s = _make_scanner()

    with patch.object(s.http, "get", return_value=_resp(200, "[]", json_data=[])):
        results = s.scan("https:///path-only")

    assert results == []


def test_crt_sh_json_decode_exception_handled():
    """Exception inside _query_crt_sh (e.g. resp.json() raises) returns empty (lines 79-81)."""
    s = _make_scanner()
    # Return a 200 response but whose .json() call raises JSONDecodeError
    bad_json_resp = MagicMock()
    bad_json_resp.status_code = 200
    bad_json_resp.text = "not-json"
    bad_json_resp.headers = {}
    bad_json_resp.json.side_effect = ValueError("No JSON object could be decoded")

    with patch.object(s.http, "get", return_value=bad_json_resp):
        results = s.scan(URL)

    # JSON parse failure → _query_crt_sh returns None → scan returns []
    assert results == []
