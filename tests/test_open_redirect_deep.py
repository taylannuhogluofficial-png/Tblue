"""Tests for Open Redirect Deep scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestOpenRedirectDeepScanner:
    def _scanner(self):
        from tblue.scanner.open_redirect_deep import OpenRedirectDeepScanner
        return OpenRedirectDeepScanner(MagicMock())

    def _resp(self, body="OK", status=200, headers=None):
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

    def test_clean_page_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>OK</html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_meta_refresh_external_warns(self):
        from tblue.scanner.open_redirect_deep import _check_meta_refresh_redirect
        body = '<meta http-equiv="refresh" content="0; url=https://evil.com/phish">'
        findings = _check_meta_refresh_redirect(body, URL)
        assert any("meta_refresh" in f["type"] for f in findings)

    def test_meta_refresh_same_origin_passes(self):
        from tblue.scanner.open_redirect_deep import _check_meta_refresh_redirect
        body = '<meta http-equiv="refresh" content="0; url=https://example.com/login">'
        findings = _check_meta_refresh_redirect(body, URL)
        assert findings == []

    def test_js_location_external_warns(self):
        from tblue.scanner.open_redirect_deep import _check_js_location_hardcoded
        body = 'location.href = "https://evil.com/phish";'
        findings = _check_js_location_hardcoded(body, URL)
        assert any("js_hardcoded" in f["type"] for f in findings)

    def test_js_location_same_origin_passes(self):
        from tblue.scanner.open_redirect_deep import _check_js_location_hardcoded
        body = 'location.href = "https://example.com/dashboard";'
        findings = _check_js_location_hardcoded(body, URL)
        assert findings == []

    def test_probe_redirect_param_fails(self):
        from tblue.scanner.open_redirect_deep import _probe_redirect_params, _PROBE_DOMAIN
        http = MagicMock()
        r = MagicMock()
        r.status_code = 302
        r.headers = {"location": f"https://{_PROBE_DOMAIN}/"}
        http.get.return_value = r
        findings = _probe_redirect_params(http, URL)
        assert any("url_param" in f["type"] for f in findings)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>clean</html>")):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
