"""Extra branch coverage for tblue.scanner.redirect_chain."""

from unittest.mock import MagicMock, patch
from tblue.scanner.redirect_chain import RedirectChainScanner

URL = "https://example.com"


def _make_scanner():
    session = MagicMock()
    s = RedirectChainScanner(session)
    return s


def _resp(status=200, location="", url=URL):
    r = MagicMock()
    r.status_code = status
    r.headers = {"Location": location} if location else {}
    r.url = url
    r.text = ""
    return r


def test_no_redirects_clean_chain():
    """Single response with 200 — no redirects, no issues detected."""
    s = _make_scanner()
    s.http.get = MagicMock(return_value=_resp(200))
    results = s.scan(URL)
    assert isinstance(results, list)
    # No FAIL for a simple 200 with no redirect chain
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not fails


def test_http_hop_before_https_destination_fails():
    """Chain with HTTP hop before final HTTPS destination triggers FAIL."""
    http_url = "http://example.com"
    s = _make_scanner()
    call_count = [0]

    def fake_get(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            # First call: HTTP, redirects to HTTPS
            r = _resp(301, "https://example.com", http_url)
            r.headers = {"Location": "https://example.com"}
            return r
        # Second call: HTTPS, no more redirect
        return _resp(200, url=URL)

    s.http.get = fake_get
    results = s.scan(http_url)
    assert isinstance(results, list)
    # The HTTP hop before HTTPS should result in a FAIL finding
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_redirect_loop_detected():
    """Redirect loop to the same URL produces a FAIL and returns None chain."""
    s = _make_scanner()
    # Always redirect to same URL = loop
    s.http.get = MagicMock(return_value=_resp(301, URL))
    results = s.scan(URL)
    fail_results = [r for r in results if "loop" in r["type"].lower()]
    assert fail_results


def test_exception_during_redirect_probe_breaks_chain():
    """Exception during HTTP probe breaks chain gracefully."""
    s = _make_scanner()
    call_count = [0]

    def fake_get(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return _resp(301, "https://example.com/step2")
        raise ConnectionError("timeout")

    s.http.get = fake_get
    results = s.scan(URL)
    assert isinstance(results, list)


def test_none_response_breaks_chain_cleanly():
    """None response from http.get breaks the chain without crash."""
    s = _make_scanner()
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert isinstance(results, list)


def test_excessive_redirects_warns():
    """More than _WARN_REDIRECTS hops produces a WARN or FAIL."""
    s = _make_scanner()
    call_count = [0]

    def fake_get(url, **kw):
        call_count[0] += 1
        n = call_count[0]
        # Return 9 redirects then a final 200
        if n <= 9:
            return _resp(301, f"https://example.com/step{n}")
        return _resp(200)

    s.http.get = fake_get
    results = s.scan(URL)
    assert isinstance(results, list)
    warns_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert warns_fails
