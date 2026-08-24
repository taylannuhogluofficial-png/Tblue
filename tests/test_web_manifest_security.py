"""Tests for Web App Manifest Security scanner."""
import json
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"
MANIFEST_URL = "https://example.com/manifest.json"


class TestWebManifestSecurityScanner:
    def _scanner(self):
        from tblue.scanner.web_manifest_security import WebManifestSecurityScanner
        return WebManifestSecurityScanner(MagicMock())

    def _resp(self, body="", status=200, ct="text/html"):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {"content-type": ct}
        r.url = URL
        return r

    def _manifest_resp(self, data: dict):
        r = MagicMock()
        r.text = json.dumps(data)
        r.status_code = 200
        r.headers = {"content-type": "application/manifest+json"}
        r.url = MANIFEST_URL
        return r

    def test_no_manifest_passes(self):
        """No manifest in HTML, no manifest at well-known paths → PASS."""
        s = self._scanner()
        not_found = self._resp("<html></html>", 404)

        def side(url):
            return not_found

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_valid_manifest_passes(self):
        """Well-configured manifest → PASS."""
        s = self._scanner()
        manifest = {
            "name": "My App",
            "start_url": "/",
            "scope": "/",
            "display": "standalone",
            "icons": [{"src": "/icon.png", "sizes": "192x192"}],
        }

        def side(url):
            if "manifest.json" in url:
                return self._manifest_resp(manifest)
            return self._resp("<html></html>", 404)

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_external_start_url_fails(self):
        """start_url pointing to different origin → FAIL."""
        s = self._scanner()
        manifest = {
            "name": "Evil App",
            "start_url": "https://attacker.com/phishing",
            "scope": "/",
            "display": "standalone",
        }

        def side(url):
            if "manifest.json" in url:
                return self._manifest_resp(manifest)
            return self._resp("<html></html>", 404)

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("start_url" in r["type"].lower() or "external" in r["type"].lower() for r in fails)

    def test_fullscreen_display_warns(self):
        """display: fullscreen → WARN."""
        s = self._scanner()
        manifest = {"name": "App", "start_url": "/", "display": "fullscreen"}

        def side(url):
            if "manifest.json" in url:
                return self._manifest_resp(manifest)
            return self._resp("<html></html>", 404)

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("fullscreen" in r["type"].lower() for r in warns)

    def test_icon_over_http_warns(self):
        """Icon src over HTTP → WARN."""
        s = self._scanner()
        manifest = {
            "name": "App",
            "start_url": "/",
            "icons": [{"src": "http://example.com/icon.png", "sizes": "192x192"}],
        }

        def side(url):
            if "manifest.json" in url:
                return self._manifest_resp(manifest)
            return self._resp("<html></html>", 404)

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("http" in r["type"].lower() or "icon" in r["type"].lower() for r in warns)

    def test_no_scope_warns(self):
        """Missing scope in manifest → WARN."""
        s = self._scanner()
        manifest = {"name": "App", "start_url": "/"}

        def side(url):
            if "manifest.json" in url:
                return self._manifest_resp(manifest)
            return self._resp("<html></html>", 404)

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("scope" in r["type"].lower() for r in warns)

    def test_manifest_link_in_html(self):
        """Manifest discovered via <link rel=manifest> → scanned."""
        s = self._scanner()
        html = '<html><head><link rel="manifest" href="/manifest.json"></head></html>'
        manifest = {"name": "App", "start_url": "/", "scope": "/", "display": "standalone"}

        def side(url):
            if url == URL:
                return self._resp(html)
            if "manifest.json" in url:
                return self._manifest_resp(manifest)
            return self._resp("<html></html>", 404)

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        # Should at least scan (not just skip)
        assert results

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html></html>", 404)):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_audit_manifest_external_start_url(self):
        from tblue.scanner.web_manifest_security import _audit_manifest
        data = {"start_url": "https://evil.com/start"}
        findings = _audit_manifest(data, "https://example.com")
        assert any(f["type"] == "manifest-external-start-url" for f in findings)

    def test_audit_manifest_fullscreen(self):
        from tblue.scanner.web_manifest_security import _audit_manifest
        data = {"display": "fullscreen"}
        findings = _audit_manifest(data, "https://example.com")
        assert any(f["type"] == "manifest-fullscreen-display" for f in findings)

    def test_audit_manifest_no_scope(self):
        from tblue.scanner.web_manifest_security import _audit_manifest
        findings = _audit_manifest({}, "https://example.com")
        assert any(f["type"] == "manifest-no-scope" for f in findings)

    def test_audit_manifest_clean(self):
        from tblue.scanner.web_manifest_security import _audit_manifest
        data = {
            "start_url": "/",
            "scope": "/",
            "display": "standalone",
            "icons": [{"src": "https://example.com/icon.png"}],
        }
        findings = _audit_manifest(data, "https://example.com")
        assert not findings
