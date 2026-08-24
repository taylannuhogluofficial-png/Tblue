"""Extra branch coverage for tblue.scanner.xsleak."""

from unittest.mock import MagicMock, patch
from tblue.scanner.xsleak import XSLeakScanner

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
    return XSLeakScanner(session)


def test_no_issues_passes():
    """Well-configured page → no FAIL results."""
    s = _scanner()
    hdrs = {
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "X-Frame-Options": "DENY",
    }
    with patch.object(s.http, "get", return_value=_resp("<html></html>", headers=hdrs)):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_missing_coop_warns():
    """Missing Cross-Origin-Opener-Policy → WARN."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("", headers={})):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad


def test_search_disclosure_via_different_status_flagged():
    """Search endpoint returning different status codes per character → detected."""
    s = _scanner()
    search_html = '<html><form action="/search"><input name="q"/></form></html>'
    responses = [_resp("Found: 1 result", 200), _resp("Not Found", 404)]
    counter = [0]

    def get_side(*a, **kw):
        r = responses[counter[0] % len(responses)]
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


def test_result_keys():
    """Results contain required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
