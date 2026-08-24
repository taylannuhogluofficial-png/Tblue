"""Tests for HTTP Strict Transport Upgrade scanner."""
from unittest.mock import MagicMock, patch

URL_HTTPS = "https://example.com"
URL_HTTP  = "http://example.com"


class TestHTTPStrictTransportUpgradeScanner:
    def _scanner(self):
        from tblue.scanner.http_strict_transport_upgrade import HTTPStrictTransportUpgradeScanner
        return HTTPStrictTransportUpgradeScanner(MagicMock())

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL_HTTPS)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_https_passes(self):
        s = self._scanner()

        def get_side(url, **kwargs):
            # HTTP probe correctly redirects to HTTPS
            if url.startswith("http://"):
                return self._resp("", 301, headers={"location": "https://example.com/"})
            return self._resp("<html>OK</html>", 200)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL_HTTPS)
        assert any(r["status"] == "PASS" for r in results)

    def test_http_no_redirect_fails(self):
        s = self._scanner()

        def get_side(url, **kwargs):
            if url.startswith("http://"):
                return self._resp("<html>OK</html>", 200)
            return self._resp("<html>OK</html>", 200)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL_HTTPS)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("no_redirect" in r["type"] or "redirect" in r["type"] for r in fails)

    def test_mixed_form_action_fails(self):
        s = self._scanner()
        body = '<form action="http://example.com/login" method="post">'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL_HTTPS)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("form_action" in r["type"] for r in fails)

    def test_mixed_links_warn(self):
        s = self._scanner()
        body = '<img src="http://cdn.example.com/image.png">'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL_HTTPS)
        found = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("mixed" in r["type"] for r in found)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL_HTTPS)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_mixed_links_detected(self):
        from tblue.scanner.http_strict_transport_upgrade import _check_mixed_links
        findings = _check_mixed_links('<img src="http://cdn.example.com/img.png">', URL_HTTPS)
        assert any("mixed" in f["type"] for f in findings)

    def test_form_action_http_fails(self):
        from tblue.scanner.http_strict_transport_upgrade import _check_mixed_links
        findings = _check_mixed_links('<form action="http://example.com/submit">', URL_HTTPS)
        assert any("form_action" in f["type"] for f in findings)

    def test_clean_page(self):
        from tblue.scanner.http_strict_transport_upgrade import _check_mixed_links
        assert _check_mixed_links("<html>OK</html>", URL_HTTPS) == []
