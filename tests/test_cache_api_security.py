"""Tests for CacheAPISecurityScanner."""
import pytest
from unittest.mock import MagicMock
from tblue.scanner.cache_api_security import CacheAPISecurityScanner


def _scanner():
    s = CacheAPISecurityScanner.__new__(CacheAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestAuthCached:
    def test_auth_response_cached_fails(self):
        s = _scanner()
        # _CACHE_AUTH_RE needs 'Authorization|Bearer|token|credential' in the second arg before first ')'
        body = """
        const cache = await caches.open('app-cache');
        cache.put('/api/profile', new Response(authToken));
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "cache_api_auth_response_cached" in types
        assert any(r["status"] == "FAIL" for r in results)


class TestSensitiveURLCached:
    def test_sensitive_endpoint_cached_warns(self):
        s = _scanner()
        body = """
        caches.open('app-v1').then(cache => {
            cache.addAll(['/static/app.js', '/api/user', '/api/profile']);
        });
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "cache_api_sensitive_url_cached" in types


class TestSensitiveCacheName:
    def test_auth_cache_name_warns(self):
        s = _scanner()
        body = "caches.open('auth-data-cache').then(c => c.addAll(['/static/main.js']));"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "cache_api_sensitive_cache_name" in types


class TestNoLogoutCacheClear:
    def test_no_cache_clear_on_logout_warns(self):
        s = _scanner()
        body = """
        function logout() { window.location.href = '/login'; }
        caches.open('app').then(c => c.addAll(['/api/user']));
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "cache_api_no_logout_clear" in types

    def test_cache_clear_on_logout_passes(self):
        s = _scanner()
        body = """
        function logout() {
            caches.keys().then(keys => keys.forEach(k => caches.delete(k)));
            window.location.href = '/login';
        }
        caches.open('app').then(c => c.addAll(['/api/user']));
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "cache_api_no_logout_clear" not in types


class TestNotUsed:
    def test_no_cache_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>No cache API</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "cache_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
