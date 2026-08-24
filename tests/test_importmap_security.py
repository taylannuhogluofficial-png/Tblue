"""Tests for ImportMapSecurityScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.importmap_security import ImportMapSecurityScanner

URL = "https://example.com"


def _page(importmap_json, count=1):
    block = f'<script type="importmap">{importmap_json}</script>'
    return f"<html><head>{block * count}</head><body></body></html>"


class TestImportMapSecurity(unittest.TestCase):
    def _make(self):
        s = ImportMapSecurityScanner.__new__(ImportMapSecurityScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", headers=None):
        r = MagicMock()
        r.status_code = 200
        r.text = body
        r.headers = headers or {}
        return r

    # ── No import map ─────────────────────────────────────────────────────────

    def test_no_importmap_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body="<html><body><script>var x=1;</script></body></html>")
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── External HTTPS without SRI ────────────────────────────────────────────

    def test_external_without_sri_warns(self):
        body = _page('{"imports": {"react": "https://cdn.jsdelivr.net/npm/react/index.js"}}')
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("sri" in r["type"].lower() or "external" in r["type"].lower() or "integrity" in r["type"].lower() for r in warns))

    # ── HTTP module URL ───────────────────────────────────────────────────────

    def test_http_module_url_fails(self):
        body = _page('{"imports": {"mylib": "http://cdn.example.com/mylib.js"}}')
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("http" in r["type"].lower() or "tls" in r["type"].lower() for r in fails))

    # ── data: module specifier ────────────────────────────────────────────────

    def test_data_uri_module_fails(self):
        body = _page('{"imports": {"evil": "data:text/javascript,alert(1)"}}')
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("data" in r["type"].lower() or "javascript" in r["type"].lower() for r in fails))

    # ── javascript: module specifier ──────────────────────────────────────────

    def test_javascript_module_fails(self):
        body = _page('{"imports": {"evil": "javascript:alert(1)"}}')
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(len(fails) > 0)

    # ── Multiple import maps ──────────────────────────────────────────────────

    def test_multiple_importmaps_warns(self):
        body = _page('{"imports": {}}', count=2)
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("multiple" in r["type"].lower() or "2" in r["type"] for r in warns))

    # ── Global scope override ─────────────────────────────────────────────────

    def test_global_scope_warns(self):
        body = _page('{"imports": {}, "scopes": {"/": {"react": "https://evil.com/react.js"}}}')
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("scope" in r["type"].lower() or "global" in r["type"].lower() or "/" in r["type"] for r in warns))

    # ── Malformed JSON ────────────────────────────────────────────────────────

    def test_malformed_json_warns(self):
        body = _page("{not valid json}")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("malformed" in r["type"].lower() or "json" in r["type"].lower() for r in warns))

    # ── No response ───────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
