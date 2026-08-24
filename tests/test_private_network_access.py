"""Tests for PrivateNetworkAccessScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.private_network_access import PrivateNetworkAccessScanner

URL_PUBLIC = "https://example.com"
URL_PRIVATE = "http://192.168.1.1"
URL_LOCAL = "http://localhost:8080"


class TestPrivateNetworkAccess(unittest.TestCase):
    def _make(self):
        s = PrivateNetworkAccessScanner.__new__(PrivateNetworkAccessScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = headers or {}
        return r

    # ── Private IP with ACAO: * fails ─────────────────────────────────────────

    def test_private_ip_with_wildcard_acao_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                body='{"users": []}',
                headers={"access-control-allow-origin": "*"}
            )
            results = s.scan(URL_PRIVATE)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("private" in r["type"].lower() or "acao" in r["type"].lower() or "*" in r["type"] for r in fails))

    # ── localhost with ACAO: * fails ──────────────────────────────────────────

    def test_localhost_with_wildcard_acao_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                body="ok",
                headers={"access-control-allow-origin": "*"}
            )
            results = s.scan(URL_LOCAL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(len(fails) > 0)

    # ── Private IP without CORS passes ────────────────────────────────────────

    def test_private_ip_no_cors_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body="OK", headers={})
            results = s.scan(URL_PRIVATE)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── Public site API with ACAO: * on 200 response warns ───────────────────

    def test_public_api_acao_wildcard_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if "/api/" in u or "/api/v1" in u:
                    return self._resp(
                        body='{"data": []}',
                        status=200,
                        headers={"access-control-allow-origin": "*"}
                    )
                return self._resp(body="<html>main</html>", headers={})
            m.get.side_effect = side_effect
            results = s.scan(URL_PUBLIC)
        warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("acao" in r["type"].lower() or "api" in r["type"].lower() or "wildcard" in r["type"].lower() or "public" in r["type"].lower() for r in warns_or_fails))

    # ── No response passes ────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL_PUBLIC)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
