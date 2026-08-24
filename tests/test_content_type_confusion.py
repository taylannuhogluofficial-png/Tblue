"""Tests for Content-Type Confusion scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestContentTypeConfusionScanner:
    def _scanner(self):
        from tblue.scanner.content_type_confusion import ContentTypeConfusionScanner
        return ContentTypeConfusionScanner(MagicMock())

    def _resp(self, body="OK", status=200, headers=None):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {"content-type": "text/html; charset=utf-8",
                                 "x-content-type-options": "nosniff"}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_missing_nosniff_warns(self):
        from tblue.scanner.content_type_confusion import _check_xcto_missing
        findings = _check_xcto_missing({}, URL)
        assert any("nosniff" in f["type"] for f in findings)

    def test_nosniff_present_passes(self):
        from tblue.scanner.content_type_confusion import _check_xcto_missing
        findings = _check_xcto_missing({"x-content-type-options": "nosniff"}, URL)
        assert findings == []

    def test_json_as_html_warns(self):
        from tblue.scanner.content_type_confusion import _check_json_served_as_html
        findings = _check_json_served_as_html('{"user": "admin"}', "text/html", URL)
        assert any("json_as_html" in f["type"] for f in findings)

    def test_svg_with_script_fails(self):
        from tblue.scanner.content_type_confusion import _check_svg_xss_risk
        findings = _check_svg_xss_risk('<svg><script>alert(1)</script></svg>', "image/svg+xml", URL)
        assert any("svg" in f["type"] for f in findings)
        assert any(f["status"] == "FAIL" for f in findings)

    def test_clean_html_passes(self):
        from tblue.scanner.content_type_confusion import _check_json_served_as_html
        findings = _check_json_served_as_html("<html><body>Hello</body></html>", "text/html", URL)
        assert findings == []

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
