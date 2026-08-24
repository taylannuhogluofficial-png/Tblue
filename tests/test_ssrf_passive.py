"""Tests for SSRF Passive scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"
URL_WITH_PARAM = "https://example.com/?url=https://google.com"

_SSRF_PROBE_PATHS = ["/fetch", "/proxy", "/redirect", "/load", "/render",
                     "/preview", "/screenshot", "/pdf", "/thumbnail", "/embed"]


class TestSSRFPassiveScanner:
    def _scanner(self):
        from tblue.scanner.ssrf_passive import SSRFPassiveScanner
        return SSRFPassiveScanner(MagicMock())

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
        def get_side(url, **kw):
            r = MagicMock()
            r.headers = {}
            if any(p in url for p in _SSRF_PROBE_PATHS + ["/import", "/export", "/webhook", "/notify", "/download", "/open", "/connect"]):
                r.status_code = 404
                r.text = "Not Found"
            else:
                r.status_code = 200
                r.text = "<html>OK</html>"
            return r
        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_metadata_ip_in_response_fails(self):
        from tblue.scanner.ssrf_passive import _check_page_for_ssrf_hints
        body = "Error connecting to 169.254.169.254/latest/meta-data"
        findings = _check_page_for_ssrf_hints(body, {}, URL)
        assert any("metadata" in f["type"] for f in findings)

    def test_ssrf_param_in_url_warns(self):
        from tblue.scanner.ssrf_passive import _check_ssrf_params_in_url
        findings = _check_ssrf_params_in_url(URL_WITH_PARAM)
        assert any("parameter" in f["type"] for f in findings)

    def test_clean_url_params_passes(self):
        from tblue.scanner.ssrf_passive import _check_ssrf_params_in_url
        findings = _check_ssrf_params_in_url("https://example.com/?q=search&page=1")
        assert findings == []

    def test_ssrf_hint_endpoint_warns(self):
        from tblue.scanner.ssrf_passive import _probe_ssrf_hint_paths
        http = MagicMock()
        r = MagicMock()
        r.status_code = 200
        r.text = "OK"
        http.get.return_value = r
        findings = _probe_ssrf_hint_paths(http, "https://example.com", URL)
        assert any("hint" in f["type"] for f in findings)

    def test_hint_404_not_flagged(self):
        from tblue.scanner.ssrf_passive import _probe_ssrf_hint_paths
        http = MagicMock()
        r = MagicMock()
        r.status_code = 404
        r.text = "Not Found"
        http.get.return_value = r
        findings = _probe_ssrf_hint_paths(http, "https://example.com", URL)
        assert findings == []

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
