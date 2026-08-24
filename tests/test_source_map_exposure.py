"""Tests for Source Map Exposure scanner."""
from unittest.mock import MagicMock, patch
URL = "https://example.com"

class TestSourceMapExposureScanner:
    def _scanner(self):
        from tblue.scanner.source_map_exposure import SourceMapExposureScanner
        return SourceMapExposureScanner(MagicMock())
    def _resp(self, body="OK", status=200, headers=None):
        r = MagicMock(); r.text = body; r.status_code = status; r.headers = headers or {}; return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None): results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_source_map_comment_warns(self):
        from tblue.scanner.source_map_exposure import _check_source_map_comment
        findings = _check_source_map_comment("//# sourceMappingURL=app.js.map\n", URL)
        assert any("comment" in f["type"] for f in findings)

    def test_no_source_map_passes(self):
        from tblue.scanner.source_map_exposure import _check_source_map_comment
        findings = _check_source_map_comment("function main() { return 1; }", URL)
        assert findings == []

    def test_map_file_accessible_fails(self):
        from tblue.scanner.source_map_exposure import _check_map_file_accessible
        http = MagicMock(); r = MagicMock(); r.status_code = 200
        r.text = '{"sources":["/home/ubuntu/app/src/main.js"],"mappings":"AAAA"}' + "x" * 100
        http.get.return_value = r
        findings = _check_map_file_accessible(http, "https://example.com/app.js")
        assert any("accessible" in f["type"] for f in findings)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>no map</html>", 404)):
            results = s.scan(URL)
        for r in results: assert r["status"] in ("PASS", "WARN", "FAIL")
