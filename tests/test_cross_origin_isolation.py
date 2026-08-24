"""Tests for CrossOriginIsolationScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.cross_origin_isolation import CrossOriginIsolationScanner

URL = "https://example.com"


class TestCrossOriginIsolation(unittest.TestCase):
    def _make(self):
        s = CrossOriginIsolationScanner.__new__(CrossOriginIsolationScanner)
        s.http = MagicMock()
        return s

    def _resp(self, status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = ""
        r.headers = headers or {}
        return r

    # ── COOP checks ────────────────────────────────────────────────────────────

    def test_missing_coop_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={})
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("coop" in r["type"].lower() or "opener" in r["type"].lower() for r in warns))

    def test_coop_unsafe_none_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={"cross-origin-opener-policy": "unsafe-none"})
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("unsafe" in r["type"].lower() or "opener" in r["type"].lower() for r in warns))

    def test_coop_same_origin_allow_popups_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "cross-origin-opener-policy": "same-origin-allow-popups",
                "cross-origin-embedder-policy": "require-corp",
                "cross-origin-resource-policy": "same-origin",
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("moderate" in r["type"].lower() or "popup" in r["type"].lower() or "allow-popup" in r["type"].lower() for r in warns))

    def test_coop_same_origin_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "cross-origin-opener-policy": "same-origin",
                "cross-origin-embedder-policy": "require-corp",
                "cross-origin-resource-policy": "same-origin",
            })
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── COEP checks ────────────────────────────────────────────────────────────

    def test_missing_coep_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "cross-origin-opener-policy": "same-origin",
                "cross-origin-resource-policy": "same-origin",
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("coep" in r["type"].lower() or "embedder" in r["type"].lower() for r in warns))

    def test_coep_unsafe_none_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "cross-origin-opener-policy": "same-origin",
                "cross-origin-embedder-policy": "unsafe-none",
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("unsafe" in r["type"].lower() or "embedder" in r["type"].lower() for r in warns))

    # ── CORP checks ────────────────────────────────────────────────────────────

    def test_missing_corp_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "cross-origin-opener-policy": "same-origin",
                "cross-origin-embedder-policy": "require-corp",
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("corp" in r["type"].lower() or "resource-policy" in r["type"].lower() for r in warns))

    def test_corp_cross_origin_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "cross-origin-opener-policy": "same-origin",
                "cross-origin-embedder-policy": "require-corp",
                "cross-origin-resource-policy": "cross-origin",
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("cross-origin" in r["type"].lower() for r in warns))

    # ── Isolation combo ────────────────────────────────────────────────────────

    def test_incomplete_isolation_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "cross-origin-opener-policy": "same-origin",
                "cross-origin-resource-policy": "same-origin",
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(len(warns) > 0)

    # ── No response ────────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
