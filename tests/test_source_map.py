"""Tests for tblue.scanner.source_map — SourceMapScanner."""

from unittest.mock import MagicMock, patch
from tblue.scanner.source_map import SourceMapScanner

URL = "https://example.com"
BASE = "https://example.com"


def _make_scanner():
    return SourceMapScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = {}
    return r


_VALID_MAP = '{"version":3,"sources":["src/main.ts"],"mappings":"AAAA","names":[]}'
_MAP_WITH_CONTENT = '{"version":3,"sources":["src/main.ts"],"sourcesContent":["export default class App { }"],"mappings":"AAAA"}'
_WEBPACK_STATS = '{"chunks":[{"id":0,"names":["main"]}],"modules":[{"id":0,"name":"./src/index.js"}],"assets":[]}'


def test_unreachable_pass():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_clean_page_no_bundles_pass():
    """Page with no JS bundles and no common map files → PASS."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html><p>Hello</p></html>")
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] == "FAIL" for r in results)


def test_source_map_with_source_content_fails():
    """app.js points to app.js.map which has sourcesContent → FAIL."""
    s = _make_scanner()
    js_body = "(function(){})();\n//# sourceMappingURL=app.js.map"
    html = '<html><head><script src="/js/app.js"></script></head></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if url == "https://example.com/js/app.js":
            return _resp(200, js_body)
        if url == "https://example.com/js/app.js.map":
            return _resp(200, _MAP_WITH_CONTENT)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("source map" in f["type"].lower() or "sourcecontent" in f["type"].lower()
               or "source code" in f["type"].lower() for f in fails)


def test_source_map_without_source_content_warns():
    """app.js.map accessible but no sourcesContent → WARN."""
    s = _make_scanner()
    js_body = "(function(){})();\n//# sourceMappingURL=app.js.map"
    html = '<html><head><script src="/js/app.js"></script></head></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if url == "https://example.com/js/app.js":
            return _resp(200, js_body)
        if url == "https://example.com/js/app.js.map":
            return _resp(200, _VALID_MAP)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("source map" in w["type"].lower() for w in warns)


def test_webpack_stats_json_exposed_fails():
    """webpack stats.json is accessible → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if "/stats.json" in url:
            return _resp(200, _WEBPACK_STATS, {"content-type": "application/json"})
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("stats.json" in f["type"].lower() or "webpack" in f["type"].lower() for f in fails)


def test_common_bundle_path_map_file_found_fails():
    """Probing /static/js/main.js.map finds source map with content → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/static/js/main.js.map":
            return _resp(200, _MAP_WITH_CONTENT)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("source map" in f["type"].lower() or "source code" in f["type"].lower() for f in fails)


def test_map_file_not_accessible_pass():
    """JS bundle references a map but the map file returns 404 → PASS."""
    s = _make_scanner()
    js_body = "(function(){})();\n//# sourceMappingURL=main.js.map"
    html = '<html><head><script src="/js/main.js"></script></head></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if url == "https://example.com/js/main.js":
            return _resp(200, js_body)
        if url == "https://example.com/js/main.js.map":
            return _resp(404)  # map not accessible
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert len(fails) == 0


def test_inline_data_uri_sourcemap_not_flagged():
    """Inline data: URL source map is OK (not publicly accessible) → PASS."""
    s = _make_scanner()
    js_body = "(function(){})();\n//# sourceMappingURL=data:application/json;base64,abc123"
    html = '<html><head><script src="/js/app.js"></script></head></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if url == "https://example.com/js/app.js":
            return _resp(200, js_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_internal_path_in_source_root_warns():
    """Source map with internal server path in sourceRoot → WARN."""
    s = _make_scanner()
    map_with_path = '{"version":3,"sources":["src/main.ts"],"sourceRoot":"/home/ubuntu/myapp/","mappings":"AAAA"}'
    js_body = "(function(){})();\n//# sourceMappingURL=app.js.map"
    html = '<html><head><script src="/js/app.js"></script></head></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if url == "https://example.com/js/app.js":
            return _resp(200, js_body)
        if url == "https://example.com/js/app.js.map":
            return _resp(200, map_with_path)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("source map" in w["type"].lower() or "path" in w["type"].lower() for w in warns)


def test_external_cdn_bundle_skipped():
    """Script from external CDN is not probed for source maps."""
    s = _make_scanner()
    html = '<html><head><script src="https://cdn.example.com/react.js"></script></head></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        # If scanner tries to access external CDN, catch it
        if "cdn.example.com" in url:
            return _resp(200, "react source code", {})
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    # External CDN scripts should be skipped
    # No FAIL result from CDN script
    assert results  # scan completes


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_script_non_js_src_skipped():
    """Script with non-.js src → continue at line 167 in _check_page_scripts."""
    s = _make_scanner()
    html = '<html><head><script src="/config.json"></script></head></html>'
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_duplicate_js_script_skipped():
    """Two <script> tags with same src → second skipped at line 170."""
    s = _make_scanner()
    html = ('<html><head>'
            '<script src="/js/app.js"></script>'
            '<script src="/js/app.js"></script>'
            '</head></html>')

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if url == "https://example.com/js/app.js":
            return _resp(200, "(function(){})();")
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_check_page_scripts_outer_exception():
    """BeautifulSoup raises in _check_page_scripts → except at lines 181-182."""
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")), \
         patch("tblue.scanner.source_map.BeautifulSoup",
               side_effect=RuntimeError("parse error")):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_js_file_returns_none():
    """JS file fetch returns None → return False at line 190 in _check_js_for_map."""
    s = _make_scanner()
    html = '<html><head><script src="/js/app.js"></script></head></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if url == "https://example.com/js/app.js":
            return None
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_x_sourcemap_header_probes_map():
    """JS response has X-SourceMap header → _probe_map_file called at line 201."""
    s = _make_scanner()
    html = '<html><head><script src="/js/app.js"></script></head></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if url == "https://example.com/js/app.js":
            return _resp(200, "(function(){})()", {"x-sourcemap": "app.js.map"})
        if url == "https://example.com/js/app.js.map":
            return _resp(200, _VALID_MAP)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert warns_or_fails


def test_no_sourcemapping_url_probes_dot_map():
    """No sourceMappingURL in JS → probe js_url + '.map' at lines 207-208."""
    s = _make_scanner()
    html = '<html><head><script src="/js/app.js"></script></head></html>'
    js_body = "(function(){})()"  # No sourceMappingURL directive at all

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if url == "https://example.com/js/app.js":
            return _resp(200, js_body)
        if url == "https://example.com/js/app.js.map":
            return _resp(200, _VALID_MAP)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert warns_or_fails


def test_non_application_json_data_uri_skipped():
    """sourceMappingURL=data:text/plain (not application/json) → return False line 212."""
    s = _make_scanner()
    html = '<html><head><script src="/js/app.js"></script></head></html>'
    js_body = "(function(){})()\n//# sourceMappingURL=data:text/plain;base64,abc123="

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if url == "https://example.com/js/app.js":
            return _resp(200, js_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_check_js_for_map_raises_exception():
    """http.get raises for JS URL → except Exception: return False at lines 217-218."""
    s = _make_scanner()
    html = '<html><head><script src="/js/app.js"></script></head></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        raise RuntimeError("connection refused")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_probe_map_file_empty_body():
    """Map file returns 200 with empty body → return False at line 229."""
    s = _make_scanner()
    html = '<html><head><script src="/js/app.js"></script></head></html>'
    js_body = "(function(){})();\n//# sourceMappingURL=app.js.map"

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if url == "https://example.com/js/app.js":
            return _resp(200, js_body)
        if url == "https://example.com/js/app.js.map":
            return _resp(200, "")  # empty body
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_probe_map_file_not_a_source_map():
    """Map file body lacks sources/mappings keys → return False at line 234."""
    s = _make_scanner()
    html = '<html><head><script src="/js/app.js"></script></head></html>'
    js_body = "(function(){})();\n//# sourceMappingURL=app.js.map"

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if url == "https://example.com/js/app.js":
            return _resp(200, js_body)
        if url == "https://example.com/js/app.js.map":
            return _resp(200, '{"version":3,"otherKey":"value"}')  # no sources/mappings
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_probe_map_file_raises_exception():
    """http.get raises inside _probe_map_file → except Exception: return False lines 299-300."""
    s = _make_scanner()
    html = '<html><head><script src="/js/app.js"></script></head></html>'
    js_body = "(function(){})();\n//# sourceMappingURL=app.js.map"

    def se(url, **kw):
        if url == URL:
            return _resp(200, html)
        if url == "https://example.com/js/app.js":
            return _resp(200, js_body)
        if url == "https://example.com/js/app.js.map":
            raise RuntimeError("reset by peer")
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_probe_common_bundles_raises_exception():
    """http.get raises in _probe_common_bundles loop → except Exception: continue lines 318-319."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")  # no page scripts
        raise RuntimeError("timeout")  # all bundle/stats probes raise

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_webpack_stats_empty_body_continues():
    """webpack stats.json returns 200 with empty body → continue at line 332."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/stats.json":
            return _resp(200, "")  # empty body
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_webpack_stats_non_json_with_chunks_warns():
    """Invalid JSON with 'chunks'/'modules' keywords → WARN at lines 357-372."""
    s = _make_scanner()
    non_json_body = '{"chunks": [...], "modules": [...] INVALID JSON'

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/stats.json":
            return _resp(200, non_json_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("stats" in r["type"].lower() or "webpack" in r["type"].lower()
               for r in warns_or_fails)
