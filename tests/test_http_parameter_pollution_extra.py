"""Extra branch coverage for tblue.scanner.http_parameter_pollution."""

from unittest.mock import MagicMock, patch
from tblue.scanner.http_parameter_pollution import HTTPParameterPollutionScanner

URL = "https://example.com"
URL_WITH_PARAM = "https://example.com/search?q=test"

_SENTINEL_A = "hpp_test_first"
_SENTINEL_B = "hpp_test_second"


def _scanner():
    session = MagicMock()
    return HTTPParameterPollutionScanner(session)


def _resp(body="", status=200):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    r.url = URL
    return r


def test_no_initial_response_returns_pass():
    """Branch: initial GET returns None → PASS result."""
    s = _scanner()
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_second_sentinel_only_echoed_is_warn():
    """Branch: only SENTINEL_B echoed (last-value preference) → WARN."""
    s = _scanner()
    call_count = [0]
    def side(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp("")  # initial
        if _SENTINEL_B in url:
            return _resp(_SENTINEL_B)
        return _resp("")
    s.http.get = MagicMock(side_effect=side)
    results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_both_sentinels_echoed_is_warn():
    """Branch: both SENTINEL_A and SENTINEL_B echoed → WARN."""
    s = _scanner()
    call_count = [0]
    def side(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp("")
        return _resp(f"{_SENTINEL_A} and {_SENTINEL_B}")
    s.http.get = MagicMock(side_effect=side)
    results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_array_notation_echoed_is_warn():
    """Branch: array notation probe value echoed in body → WARN."""
    s = _scanner()
    call_count = [0]
    def side(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp("")
        if "[]" in url or "[0]" in url:
            return _resp(_SENTINEL_A)
        return _resp("")
    s.http.get = MagicMock(side_effect=side)
    results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_no_echo_returns_pass():
    """Branch: no sentinel echoed in any probe → PASS."""
    s = _scanner()
    s.http.get = MagicMock(return_value=_resp("safe content"))
    results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_url_with_existing_param_uses_it():
    """Branch: URL already has query param → test_param picks existing key."""
    s = _scanner()
    s.http.get = MagicMock(return_value=_resp("safe content"))
    results = s.scan(URL_WITH_PARAM)
    assert isinstance(results, list)
    assert any("status" in r for r in results)
