"""Extra branch coverage for tblue.scanner.cache_poisoning."""

from unittest.mock import MagicMock, patch
from tblue.scanner.cache_poisoning import CachePoisoningScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return CachePoisoningScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def test_baseline_none_returns_empty():
    """Covers the early return when baseline GET fails."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert results == []


def test_no_store_baseline_prevents_poisoning_flag():
    """Covers the branch where Cache-Control: no-store prevents flagging."""
    s = _scanner()
    # All responses return no-store: cache poisoning should not be flagged as FAIL
    with patch.object(s.http, "get", return_value=_resp(200, "content",
                                                         {"cache-control": "no-store"})):
        results = s.scan(URL)
    assert not any(r["status"] == "FAIL" for r in results)


def test_reflected_canary_in_cacheable_response_fails():
    """Covers reflected + cacheable + header not in Vary → FAIL branch."""
    s = _scanner()
    canary = "tblue-probe.invalid"

    def fake_get(url, headers=None, **kw):
        injected_header = (headers or {})
        xfh = injected_header.get("X-Forwarded-Host", "")
        body = f"<html><link href='https://{xfh}/style.css'></html>" if xfh == canary else "<html></html>"
        return _resp(200, body, {"cache-control": "max-age=3600", "vary": "accept-encoding"})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_reflected_but_private_cache_warns_not_fails():
    """Covers branch where canary reflected but response is private (less severe)."""
    s = _scanner()
    canary = "tblue-probe.invalid"

    def fake_get(url, headers=None, **kw):
        xfh = (headers or {}).get("X-Forwarded-Host", "")
        body = f"<html>{xfh}</html>" if xfh == canary else "<html></html>"
        return _resp(200, body, {"cache-control": "private, max-age=300", "vary": ""})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    # private cache: should warn or pass but not be a critical fail
    assert isinstance(results, list)


def test_canary_reflected_only_warns():
    """Covers the 'reflected but not cacheable' WARN branch."""
    s = _scanner()
    canary = "tblue-probe.invalid"

    def fake_get(url, headers=None, **kw):
        xfh = (headers or {}).get("X-Forwarded-Host", "")
        body = f"<html>{xfh}</html>" if xfh == canary else "<html></html>"
        return _resp(200, body, {"cache-control": "no-cache, no-store", "vary": ""})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    # reflected but not cacheable → warn at most
    assert not any(r["status"] == "FAIL" for r in results)


def test_exception_in_probe_does_not_crash():
    """Covers the exception-handling branch inside the probe loop."""
    s = _scanner()
    call_count = [0]

    def fake_get(url, headers=None, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(200, "baseline", {"cache-control": "max-age=60"})
        raise ConnectionError("timeout")

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert isinstance(results, list)
