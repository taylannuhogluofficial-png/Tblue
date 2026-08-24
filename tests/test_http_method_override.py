"""Tests for HTTP Method Override scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestHTTPMethodOverrideScanner:
    def _scanner(self):
        from tblue.scanner.http_method_override import HTTPMethodOverrideScanner
        return HTTPMethodOverrideScanner(MagicMock())

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
        # When override headers present → 405; otherwise 200 with safe Allow header
        def get_side(url, headers=None, **kwargs):
            if headers:
                return self._resp("Method Not Allowed", 405, headers={"allow": "GET, POST"})
            return self._resp("<html>OK</html>", 200, headers={"allow": "GET, POST"})
        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_form_method_tunnel_warns(self):
        from tblue.scanner.http_method_override import _check_form_method_tunneling
        body = '<form><input name="_method" value="DELETE" type="hidden"></form>'
        findings = _check_form_method_tunneling(body, URL)
        assert any("tunnel" in f["type"] for f in findings)

    def test_form_method_get_not_flagged(self):
        from tblue.scanner.http_method_override import _check_form_method_tunneling
        body = '<form><input name="_method" value="GET" type="hidden"></form>'
        findings = _check_form_method_tunneling(body, URL)
        assert findings == []

    def test_override_accepted_warns(self):
        from tblue.scanner.http_method_override import _check_override_headers_reflected
        http = MagicMock()
        r = MagicMock()
        r.status_code = 200
        r.text = "OK"
        http.get.return_value = r
        findings = _check_override_headers_reflected(http, URL)
        assert any("accepted" in f["type"] for f in findings)

    def test_dangerous_allow_header_warns(self):
        from tblue.scanner.http_method_override import _check_options_allows_override
        http = MagicMock()
        r = MagicMock()
        r.status_code = 200
        r.headers = {"allow": "GET, POST, DELETE, PUT"}
        http.get.return_value = r
        findings = _check_options_allows_override(http, URL)
        assert any("dangerous" in f["type"] for f in findings)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
