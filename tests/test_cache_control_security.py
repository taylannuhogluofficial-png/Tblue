"""Tests for Cache-Control Security scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestCacheControlSecurityScanner:
    def _scanner(self):
        from tblue.scanner.cache_control_security import CacheControlSecurityScanner
        return CacheControlSecurityScanner(MagicMock())

    def _resp(self, status=200, headers=None):
        r = MagicMock()
        r.text = "<html></html>"
        r.status_code = status
        r.headers = headers or {}
        r.url = URL
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_root_with_no_store_passes(self):
        """Root page with strict no-store → no issues."""
        s = self._scanner()
        root_resp = self._resp(headers={"cache-control": "no-store, no-cache, must-revalidate"})
        with patch.object(s.http, "get", return_value=root_resp):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert not fails

    def test_sensitive_path_no_cache_control_warns(self):
        """Login page with no Cache-Control header → WARN."""
        s = self._scanner()
        root_resp = self._resp(headers={"cache-control": "no-store"})

        login_resp = self._resp(200, {})  # no cache-control at all
        login_resp.url = URL + "/login"

        def get_side_effect(url):
            if "/login" in url:
                return login_resp
            return root_resp

        with patch.object(s.http, "get", side_effect=get_side_effect):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("Cache-Control" in r["type"] for r in warns)

    def test_sensitive_path_public_cache_fails(self):
        """Login page with Cache-Control: public → FAIL."""
        s = self._scanner()
        root_resp = self._resp(headers={"cache-control": "no-store"})
        login_resp = self._resp(200, {"cache-control": "public, max-age=3600"})
        login_resp.url = URL + "/login"

        def get_side_effect(url):
            if "/login" in url:
                return login_resp
            return root_resp

        with patch.object(s.http, "get", side_effect=get_side_effect):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("cached by proxies" in r["type"] or "cacheable" in r["type"].lower() for r in fails)

    def test_set_cookie_with_cacheable_response_fails(self):
        """Response sets cookie without private/no-store → FAIL."""
        s = self._scanner()
        resp = self._resp(headers={
            "cache-control": "max-age=3600",
            "set-cookie": "sessionid=abc123; Path=/; HttpOnly"
        })
        with patch.object(s.http, "get", return_value=resp):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("Set-Cookie" in r["type"] or "cookie" in r["type"].lower() for r in fails)

    def test_api_with_s_maxage_warns(self):
        """API endpoint with s-maxage → WARN (shared cache risk)."""
        s = self._scanner()
        root_resp = self._resp(headers={"cache-control": "no-store"})
        api_resp = self._resp(200, {"cache-control": "public, s-maxage=300"})
        api_resp.url = URL + "/api/users"

        def get_side_effect(url):
            if "/api/" in url:
                return api_resp
            return root_resp

        with patch.object(s.http, "get", side_effect=get_side_effect):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("s-maxage" in r["type"].lower() for r in warns)

    def test_long_max_age_on_dynamic_page_warns(self):
        """Very long max-age on non-static resource → WARN."""
        s = self._scanner()
        resp = self._resp(headers={"cache-control": "max-age=31536000"})

        with patch.object(s.http, "get", return_value=resp):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("max-age" in r["type"].lower() for r in warns)

    def test_set_cookie_with_private_no_store_passes(self):
        """Set-Cookie with private+no-store → should not FAIL on cookie issue."""
        s = self._scanner()
        resp = self._resp(headers={
            "cache-control": "no-store, private",
            "set-cookie": "sessionid=abc123; HttpOnly"
        })
        with patch.object(s.http, "get", return_value=resp):
            results = s.scan(URL)
        cookie_fails = [r for r in results if "Set-Cookie" in r.get("type", "") and r["status"] == "FAIL"]
        assert not cookie_fails

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_parse_no_store(self):
        from tblue.scanner.cache_control_security import _parse_cache_control
        d = _parse_cache_control("no-store, no-cache, must-revalidate")
        assert d.get("no-store")
        assert d.get("no-cache")

    def test_parse_max_age(self):
        from tblue.scanner.cache_control_security import _parse_cache_control
        d = _parse_cache_control("public, max-age=3600")
        assert d.get("max-age") == 3600

    def test_parse_s_maxage(self):
        from tblue.scanner.cache_control_security import _parse_cache_control
        d = _parse_cache_control("public, s-maxage=300, max-age=60")
        assert d.get("s-maxage") == 300

    def test_is_safely_not_cached_no_store(self):
        from tblue.scanner.cache_control_security import _is_safely_not_cached
        assert _is_safely_not_cached({"no-store": True})

    def test_is_safely_not_cached_private_no_cache(self):
        from tblue.scanner.cache_control_security import _is_safely_not_cached
        assert _is_safely_not_cached({"private": True, "no-cache": True})

    def test_is_safely_not_cached_public(self):
        from tblue.scanner.cache_control_security import _is_safely_not_cached
        assert not _is_safely_not_cached({"public": True, "max-age": 3600})
