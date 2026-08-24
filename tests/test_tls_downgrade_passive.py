"""Tests for TLS Downgrade Passive scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"
HTTP_URL = "http://example.com"


class TestTLSDowngradePassiveScanner:
    def _scanner(self):
        from tblue.scanner.tls_downgrade_passive import TLSDowngradePassiveScanner
        return TLSDowngradePassiveScanner(MagicMock())

    def _resp(self, headers=None, body="", status=200):
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

    def test_missing_upgrade_insecure_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"content-security-policy": "default-src 'self'"})):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("upgrade" in r["type"] for r in warns)

    def test_has_upgrade_insecure_passes_that_check(self):
        s = self._scanner()
        headers = {"content-security-policy": "default-src 'self'; upgrade-insecure-requests"}

        def get_side(url, **kwargs):
            if url.startswith("http://"):
                return self._resp(status=301)
            return self._resp(headers)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert not any("upgrade" in r["type"] for r in results)

    def test_meta_refresh_to_http_fails(self):
        s = self._scanner()
        body = '<meta http-equiv="refresh" content="0;url=http://example.com/page">'
        headers = {"content-security-policy": "upgrade-insecure-requests"}
        with patch.object(s.http, "get", return_value=self._resp(headers, body=body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("meta" in r["type"] or "refresh" in r["type"] for r in fails)

    def test_http_endpoint_accessible_warns(self):
        s = self._scanner()
        headers = {"content-security-policy": "upgrade-insecure-requests"}

        def get_side(url, **kwargs):
            if url.startswith("http://"):
                return self._resp(status=200)
            return self._resp(headers)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("http" in r["type"] for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_upgrade_missing(self):
        from tblue.scanner.tls_downgrade_passive import _check_upgrade_insecure_requests
        result = _check_upgrade_insecure_requests({"content-security-policy": "default-src 'self'"}, URL)
        assert result is not None

    def test_check_upgrade_present(self):
        from tblue.scanner.tls_downgrade_passive import _check_upgrade_insecure_requests
        result = _check_upgrade_insecure_requests(
            {"content-security-policy": "default-src 'self'; upgrade-insecure-requests"}, URL)
        assert result is None

    def test_meta_refresh_http(self):
        from tblue.scanner.tls_downgrade_passive import _check_meta_refresh_http
        body = '<meta http-equiv="refresh" content="0;url=http://evil.com">'
        result = _check_meta_refresh_http(body, URL)
        assert result is not None

    def test_meta_refresh_https_ok(self):
        from tblue.scanner.tls_downgrade_passive import _check_meta_refresh_http
        body = '<meta http-equiv="refresh" content="0;url=https://example.com">'
        result = _check_meta_refresh_http(body, URL)
        assert result is None
