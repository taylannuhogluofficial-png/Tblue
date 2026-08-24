"""Tests for Source Map Exposure scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestSourceMapExposureScanner:
    def _scanner(self):
        from tblue.scanner.sourcemap_exposure import SourceMapExposureScanner
        return SourceMapExposureScanner(MagicMock())

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_maps_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(status=404)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_map_file_accessible_warns(self):
        s = self._scanner()
        map_content = '{"version":3,"sources":["../src/app.ts"],"mappings":"..."}'

        def get_side(url, **kwargs):
            if url.endswith(".map"):
                return self._resp(map_content, 200)
            return self._resp(status=404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("sourcemap" in r["type"] for r in warns)

    def test_inline_sourcemap_warns(self):
        s = self._scanner()
        js_body = "var x=1;\n//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ=="

        def get_side(url, **kwargs):
            if "main.js" in url or "app.js" in url:
                return self._resp(js_body, 200)
            return self._resp(status=404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("inline" in r["type"] for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(status=404)):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_inline_sourcemap(self):
        from tblue.scanner.sourcemap_exposure import _check_inline_sourcemap
        body = "//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ=="
        result = _check_inline_sourcemap(body, URL)
        assert result is not None

    def test_check_no_inline_map(self):
        from tblue.scanner.sourcemap_exposure import _check_inline_sourcemap
        result = _check_inline_sourcemap("var x = 1;", URL)
        assert result is None

    def test_scan_for_key_patterns(self):
        from tblue.scanner.sourcemap_exposure import _check_inline_sourcemap
        body = "//# sourceMappingURL=data:application/json;base64,abc"
        result = _check_inline_sourcemap(body, URL)
        assert result is not None
        assert result["status"] == "WARN"
