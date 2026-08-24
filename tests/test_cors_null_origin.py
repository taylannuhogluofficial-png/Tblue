"""Tests for CORSNullOriginScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.cors_null_origin import CORSNullOriginScanner

URL = "https://example.com"


class TestCORSNullOrigin(unittest.TestCase):
    def _make(self):
        s = CORSNullOriginScanner.__new__(CORSNullOriginScanner)
        s.http = MagicMock()
        return s

    def _resp(self, status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = ""
        r.headers = headers or {}
        return r

    # ── Null origin allowed with credentials ──────────────────────────────────

    def test_null_origin_with_credentials_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "access-control-allow-origin": "null",
                "access-control-allow-credentials": "true",
            })
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("null" in r["type"].lower() or "credential" in r["type"].lower() for r in fails))

    # ── Null origin allowed without credentials ───────────────────────────────

    def test_null_origin_without_credentials_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "access-control-allow-origin": "null",
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("null" in r["type"].lower() for r in warns))

    # ── Null origin rejected ──────────────────────────────────────────────────

    def test_null_origin_rejected_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "access-control-allow-origin": "https://example.com",
            })
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── No CORS headers ───────────────────────────────────────────────────────

    def test_no_cors_headers_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={})
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── No response ────────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
