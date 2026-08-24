"""Tests for HTTP Caching Security scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestHTTPCachingSecurityScanner:
    def _scanner(self):
        from tblue.scanner.http_caching_security import HTTPCachingSecurityScanner
        return HTTPCachingSecurityScanner(MagicMock())

    def _resp(self, headers=None, body="<html>ok</html>", status=200):
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

    def test_good_cache_control_passes(self):
        s = self._scanner()
        headers = {"cache-control": "no-store, no-cache, private", "content-type": "text/html"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        # Should not warn about missing no-store for the root path (not an auth path)
        assert any(r["status"] == "PASS" for r in results)

    def test_public_on_auth_path_fails(self):
        s = self._scanner()
        headers = {
            "cache-control": "public, max-age=3600",
            "content-type": "text/html",
        }
        dashboard_resp = self._resp(headers)

        def get_side(url, **kwargs):
            if "/dashboard" in url:
                return dashboard_resp
            return self._resp(status=404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("public" in r["type"].lower() or "auth" in r["type"].lower() for r in fails)

    def test_pragma_only_warns(self):
        s = self._scanner()
        headers = {"pragma": "no-cache", "content-type": "text/html"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("pragma" in r["type"].lower() for r in warns)

    def test_html_long_max_age_warns(self):
        s = self._scanner()
        headers = {"cache-control": "max-age=86400", "content-type": "text/html; charset=utf-8"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("max-age" in r["type"].lower() or "long" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_cache_public_on_auth(self):
        from tblue.scanner.http_caching_security import _check_cache_headers
        headers = {"cache-control": "public, max-age=3600", "content-type": "text/html"}
        findings = _check_cache_headers(headers, "", "https://example.com/dashboard", True)
        assert any("public" in f["type"].lower() for f in findings)

    def test_check_cache_pragma_only(self):
        from tblue.scanner.http_caching_security import _check_cache_headers
        headers = {"pragma": "no-cache", "content-type": "text/html"}
        findings = _check_cache_headers(headers, "", "https://example.com", False)
        assert any("pragma" in f["type"].lower() for f in findings)

    def test_check_cache_no_store_ok(self):
        from tblue.scanner.http_caching_security import _check_cache_headers
        headers = {"cache-control": "no-store, no-cache, private", "content-type": "text/html"}
        findings = _check_cache_headers(headers, "", "https://example.com/dashboard", True)
        assert not any("no-store" in f["type"] for f in findings)

    def test_check_cache_html_long_max_age(self):
        from tblue.scanner.http_caching_security import _check_cache_headers
        headers = {"cache-control": "max-age=86400", "content-type": "text/html"}
        findings = _check_cache_headers(headers, "", "https://example.com", False)
        assert any("max-age" in f["type"].lower() for f in findings)
