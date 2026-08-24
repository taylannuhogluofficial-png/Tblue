"""Tests for LinkResourceHintsSecurityScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.link_resource_hints_security import LinkResourceHintsSecurityScanner

URL = "https://example.com"


def _page(link_tag):
    return f"<html><head>{link_tag}</head><body>hello</body></html>"


class TestLinkResourceHintsSecurity(unittest.TestCase):
    def _make(self):
        s = LinkResourceHintsSecurityScanner.__new__(LinkResourceHintsSecurityScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = headers or {}
        return r

    # ── No hints ──────────────────────────────────────────────────────────────

    def test_no_hints_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body="<html><body>hello</body></html>")
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── RFC-1918 dns-prefetch ─────────────────────────────────────────────────

    def test_dns_prefetch_to_private_ip_fails(self):
        body = _page('<link rel="dns-prefetch" href="//10.0.0.50">')
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("internal" in r["type"].lower() or "private" in r["type"].lower() or "10.0.0.50" in r["type"] for r in fails))

    def test_preconnect_to_private_ip_fails(self):
        body = _page('<link rel="preconnect" href="https://192.168.1.100">')
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(len(fails) > 0)

    # ── Internal hostname ─────────────────────────────────────────────────────

    def test_dns_prefetch_to_internal_hostname_warns(self):
        body = _page('<link rel="dns-prefetch" href="//api.internal">')
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("internal" in r["type"].lower() for r in warns))

    def test_preconnect_to_corp_hostname_warns(self):
        body = _page('<link rel="preconnect" href="https://collector.corp">')
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(len(warns) > 0)

    # ── Sensitive path prefetch ───────────────────────────────────────────────

    def test_prefetch_admin_path_warns(self):
        body = _page('<link rel="prefetch" href="/admin/dashboard">')
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("sensitive" in r["type"].lower() or "admin" in r["type"].lower() for r in warns))

    def test_prefetch_api_secret_path_warns(self):
        body = _page('<link rel="preload" href="/api/v1/user/token" as="fetch">')
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(len(warns) > 0)

    # ── CDN modulepreload without SRI ─────────────────────────────────────────

    def test_modulepreload_cdn_without_sri_warns(self):
        body = _page('<link rel="modulepreload" href="https://cdn.jsdelivr.net/npm/lodash/lodash.js">')
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("cdn" in r["type"].lower() or "integrity" in r["type"].lower() or "sri" in r["type"].lower() for r in warns))

    def test_modulepreload_cdn_with_sri_passes(self):
        body = _page(
            '<link rel="modulepreload" href="https://cdn.jsdelivr.net/npm/lodash/lodash.js" '
            'integrity="sha384-abc123" crossorigin="anonymous">'
        )
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── Cross-origin preload without crossorigin ──────────────────────────────

    def test_cross_origin_preload_without_crossorigin_warns(self):
        body = _page('<link rel="preload" href="https://cdn.example.net/app.js" as="script">')
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("crossorigin" in r["type"].lower() for r in warns))

    # ── Safe hint ─────────────────────────────────────────────────────────────

    def test_safe_preload_passes(self):
        body = _page('<link rel="preload" href="/static/main.css" as="style">')
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── No response ────────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
