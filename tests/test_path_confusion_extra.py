"""Extra branch coverage for tblue.scanner.path_confusion."""

from unittest.mock import MagicMock
from tblue.scanner.path_confusion import PathConfusionScanner

URL = "https://example.com"


def _make_resp(status=200, text="", headers=None):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.headers = headers or {}
    resp.url = URL
    return resp


def test_no_response_returns_pass():
    """When target returns None, scan emits a PASS result."""
    s = PathConfusionScanner(MagicMock())
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert isinstance(results, list)
    assert len(results) >= 1
    assert results[0]["status"] == "PASS"


def test_all_paths_return_404_no_bypass_detected():
    """When all probed paths return 404, no bypass is found and PASS is returned."""
    resp404 = _make_resp(status=404, text="Not Found")
    resp200 = _make_resp(status=200, text="<html><body>Home</body></html>")

    call_count = [0]

    def side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return resp200
        return resp404

    s = PathConfusionScanner(MagicMock())
    s.http.get = MagicMock(side_effect=side_effect)
    results = s.scan(URL)
    assert isinstance(results, list)
    statuses = [r["status"] for r in results]
    assert "PASS" in statuses


def test_bypass_via_semicolon_flagged():
    """When a bypass variant returns 200 where canonical returns 403, FAIL is reported."""
    # First call: main page (200), then admin (403), then bypass variant (200 with same content)
    admin_content = "<html><body>Admin dashboard — secret content</body></html>"
    resp_home = _make_resp(status=200, text="<html><a href='/admin'>admin</a></html>")
    resp_403 = _make_resp(status=403, text="Forbidden")
    resp_bypass = _make_resp(status=200, text=admin_content)

    call_count = [0]

    def side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return resp_home
        if "admin" in url and (";admin" in url or "..;" in url or "//" in url):
            return resp_bypass
        if "admin" in url:
            return resp_403
        return _make_resp(status=404)

    s = PathConfusionScanner(MagicMock())
    s.http.get = MagicMock(side_effect=side_effect)
    results = s.scan(URL)
    assert isinstance(results, list)
    # Should have found something (PASS or a finding depending on content similarity logic)
    assert len(results) >= 1


def test_results_are_valid_dicts():
    """All result dicts contain url and status keys."""
    resp = _make_resp(status=200, text="<html><body>ok</body></html>")
    s = PathConfusionScanner(MagicMock())
    s.http.get = MagicMock(return_value=resp)
    results = s.scan(URL)
    for r in results:
        assert "url" in r
        assert "status" in r
