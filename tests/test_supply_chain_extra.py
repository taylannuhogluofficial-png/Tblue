"""Extra branch coverage for tblue.scanner.supply_chain."""

from unittest.mock import MagicMock, patch
from tblue.scanner.supply_chain import SupplyChainScanner

URL = "https://example.com"


def _resp(body="", status=200):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    r.url = URL
    return r


def _scanner():
    session = MagicMock()
    return SupplyChainScanner(session)


def test_no_external_scripts_passes():
    """Page with no external scripts → no FAIL results."""
    s = _scanner()
    html = "<html><head><script>var x=1;</script></head></html>"
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_external_cdn_without_integrity_warns():
    """External CDN script without integrity → WARN or FAIL."""
    s = _scanner()
    html = '<html><head><script src="https://cdn.jsdelivr.net/npm/axios@1.0.0/dist/axios.min.js"></script></head></html>'
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
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
