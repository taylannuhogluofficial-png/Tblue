"""Tests for CORSExposeHeadersScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.cors_expose_headers import CORSExposeHeadersScanner

URL = "https://example.com/api/data"


class TestCORSExposeHeaders(unittest.TestCase):
    def _make(self):
        s = CORSExposeHeadersScanner.__new__(CORSExposeHeadersScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = headers or {}
        return r

    # ── Sensitive header exposure ─────────────────────────────────────────────

    def test_authorization_in_aceh_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                '{"data":"ok"}',
                headers={
                    "access-control-allow-origin": "https://trusted.com",
                    "access-control-expose-headers": "Content-Length, Authorization",
                }
            )
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("authorization" in r["type"].lower() or "sensitive" in r["type"].lower() for r in fails))

    def test_x_api_key_in_aceh_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                '{"data":"ok"}',
                headers={
                    "access-control-allow-origin": "https://trusted.com",
                    "access-control-expose-headers": "X-API-Key, X-Request-ID",
                }
            )
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("x-api-key" in r["type"].lower() or "sensitive" in r["type"].lower() for r in fails))

    def test_safe_headers_in_aceh_pass(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                '{"data":"ok"}',
                headers={
                    "access-control-allow-origin": "https://trusted.com",
                    "access-control-expose-headers": "Content-Length, X-Request-ID",
                    "vary": "Origin",
                }
            )
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── Wildcard expose ───────────────────────────────────────────────────────

    def test_wildcard_expose_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                '{"data":"ok"}',
                headers={
                    "access-control-allow-origin": "https://trusted.com",
                    "access-control-expose-headers": "*",
                }
            )
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("wildcard" in r["type"].lower() or "*" in r["type"] for r in warns))

    # ── With credentials ──────────────────────────────────────────────────────

    def test_expose_with_credentials_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                '{"data":"ok"}',
                headers={
                    "access-control-allow-origin": "https://trusted.com",
                    "access-control-allow-credentials": "true",
                    "access-control-expose-headers": "Content-Length, X-Request-ID",
                    "vary": "Origin",
                }
            )
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("credential" in r["type"].lower() for r in warns))

    # ── Missing Vary: Origin ──────────────────────────────────────────────────

    def test_missing_vary_origin_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                '{"data":"ok"}',
                headers={
                    "access-control-allow-origin": "https://trusted.com",
                    "access-control-expose-headers": "Content-Length",
                }
            )
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("vary" in r["type"].lower() for r in warns))

    # ── No CORS headers ───────────────────────────────────────────────────────

    def test_no_cors_headers_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp('{"data":"ok"}', headers={})
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
