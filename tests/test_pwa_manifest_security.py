"""Tests for PWAManifestSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.pwa_manifest_security import PWAManifestSecurityScanner


def _scanner():
    s = PWAManifestSecurityScanner.__new__(PWAManifestSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestExternalStartURL:
    def test_external_start_url_fails(self):
        s = _scanner()
        # _PWA_EXTERNAL_START_URL_RE: "start_url": "https://..."
        body = '{"name": "App", "start_url": "https://evil.com/start", "scope": "/app"}'
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "pwa_external_start_url" in types


class TestOverlyBroadScope:
    def test_broad_scope_warns(self):
        s = _scanner()
        # _PWA_OVERLY_BROAD_SCOPE_RE: "scope": "/"
        body = '{"name": "App", "start_url": "/", "scope": "/"}'
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "pwa_overly_broad_scope" in types


class TestHandleLinks:
    def test_handle_links_preferred_warns(self):
        s = _scanner()
        # _PWA_HANDLE_LINKS_RE: "handle_links": "preferred"
        body = '{"name": "App", "start_url": "/", "handle_links": "preferred"}'
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "pwa_handle_links_preferred" in types


class TestNotUsed:
    def test_no_manifest_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "pwa_manifest_not_found"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
