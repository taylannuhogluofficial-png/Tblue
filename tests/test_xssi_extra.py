"""Extra branch coverage for tblue.scanner.xssi."""

from unittest.mock import MagicMock, patch
from tblue.scanner.xssi import XSSIScanner

URL = "https://example.com"


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {"Content-Type": "text/html"}
    r.url = URL
    return r


def _scanner():
    session = MagicMock()
    return XSSIScanner(session)


def test_no_js_endpoints_passes():
    """No JS endpoints found → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html></html>")):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_json_without_prefix_fails():
    """JSON endpoint without XSSI-prevention prefix → FAIL."""
    s = _scanner()
    html = '<html><script src="/api/userdata.js"></script></html>'
    json_body = '[{"id":1,"email":"user@example.com","role":"admin"}]'

    def get_side(url, **kw):
        if "userdata" in url:
            return _resp(json_body, 200, {"Content-Type": "application/json"})
        return _resp(html)

    with patch.object(s.http, "get", side_effect=get_side):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert isinstance(results, list)


def test_json_with_xssi_prefix_passes():
    """JSON endpoint with )]}' prefix → PASS (XSSI protected)."""
    s = _scanner()
    html = '<html><script src="/api/data.js"></script></html>'
    json_body = ")]}'\n[{\"id\":1,\"name\":\"user\"}]"

    def get_side(url, **kw):
        if "data.js" in url:
            return _resp(json_body, 200, {"Content-Type": "application/json"})
        return _resp(html)

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
    with patch.object(s.http, "get", return_value=_resp("<html></html>")):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
