"""Extra branch coverage for tblue.scanner.source_map."""

from unittest.mock import MagicMock, patch
from tblue.scanner.source_map import SourceMapScanner

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
    return SourceMapScanner(session)


def test_no_js_no_source_map_passes():
    """No JS files found and no map files → PASS."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html></html>", 200)):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_exposed_source_map_fails():
    """JS file with sourceMappingURL pointing to accessible .map with sources+mappings → FAIL."""
    s = _scanner()
    html = '<html><head><script src="/app.js"></script></head></html>'
    js_with_map = 'var x=1;\n//# sourceMappingURL=app.js.map'
    # Map content must have both "sources" and "mappings" keys for scanner to flag it
    map_content = '{"version":3,"sources":["src/app.ts"],"mappings":"AAAA"}'

    def get_side(url, **kw):
        if url.endswith(".map"):
            return _resp(map_content, 200, {"Content-Type": "application/json"})
        if url.endswith(".js"):
            return _resp(js_with_map, 200, {"Content-Type": "application/javascript"})
        if url == URL:
            return _resp(html)
        return _resp("", 404)

    with patch.object(s.http, "get", side_effect=get_side):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad


def test_source_map_404_passes():
    """JS with sourceMappingURL but map returns 404 → PASS (map not exposed)."""
    s = _scanner()
    html = '<html><head><script src="/app.js"></script></head></html>'
    js_with_map = 'var x=1;\n//# sourceMappingURL=app.js.map'

    def get_side(url, **kw):
        if url.endswith(".map"):
            return _resp("Not Found", 404)
        if url.endswith(".js"):
            return _resp(js_with_map, 200)
        if url == URL:
            return _resp(html)
        return _resp("", 404)

    with patch.object(s.http, "get", side_effect=get_side):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_none_response_no_fail():
    """None response → PASS result, no FAIL."""
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
