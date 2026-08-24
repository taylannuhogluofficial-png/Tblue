"""Tests for JSSupplyChainIntegrityScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.js_supply_chain_integrity import JSSupplyChainIntegrityScanner

URL = "https://example.com"


class TestJSSupplyChainIntegrity(unittest.TestCase):
    def _make(self):
        s = JSSupplyChainIntegrityScanner.__new__(JSSupplyChainIntegrityScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", headers=None):
        r = MagicMock()
        r.status_code = 200
        r.text = body
        r.headers = headers or {}
        return r

    # ── No external scripts ───────────────────────────────────────────────────

    def test_no_external_scripts_passes(self):
        body = "<html><head></head><body><script>var x=1;</script></body></html>"
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── Popular CDN without SRI fails ────────────────────────────────────────

    def test_popular_cdn_without_sri_fails(self):
        body = '<html><head><script src="https://cdn.jsdelivr.net/npm/jquery/dist/jquery.min.js"></script></head></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("sri" in r["type"].lower() or "supply chain" in r["type"].lower() or "integrity" in r["type"].lower() for r in fails))

    # ── External non-CDN without SRI warns ───────────────────────────────────

    def test_external_without_sri_warns(self):
        body = '<html><head><script src="https://assets.mycorp.io/app.js"></script></head></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(len(warns_or_fails) > 0)

    # ── SRI without crossorigin warns ────────────────────────────────────────

    def test_sri_without_crossorigin_warns(self):
        body = (
            '<html><head>'
            '<script src="https://cdn.jsdelivr.net/npm/react.js" '
            'integrity="sha384-abc123"></script>'
            '</head></html>'
        )
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("crossorigin" in r["type"].lower() or "sri" in r["type"].lower() for r in warns))

    # ── SRI with crossorigin passes ───────────────────────────────────────────

    def test_sri_with_crossorigin_passes(self):
        body = (
            '<html><head>'
            '<script src="https://cdn.jsdelivr.net/npm/react.js" '
            'integrity="sha384-abc123" crossorigin="anonymous"></script>'
            '</head></html>'
        )
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── Dynamic import of external URL warns ─────────────────────────────────

    def test_dynamic_import_external_warns(self):
        body = '<html><body><script>import("https://cdn.external.com/lib.js").then(m => m.init());</script></body></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("dynamic" in r["type"].lower() or "import" in r["type"].lower() for r in warns))

    # ── Mixed SRI posture warns ───────────────────────────────────────────────

    def test_mixed_sri_posture_warns(self):
        body = (
            '<html><head>'
            '<script src="https://cdn.jsdelivr.net/npm/react.js" '
            'integrity="sha384-abc123" crossorigin="anonymous"></script>'
            '<script src="https://cdn.jsdelivr.net/npm/lodash.js"></script>'
            '</head></html>'
        )
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(len(warns) > 0)

    # ── Module preload without SRI ────────────────────────────────────────────

    def test_modulepreload_without_sri_warns(self):
        body = '<html><head><link rel="modulepreload" href="https://cdn.example.com/module.js"></head></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(len(warns_or_fails) > 0)

    # ── No response ───────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
