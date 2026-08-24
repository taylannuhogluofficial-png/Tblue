"""Tests for HTTP2RapidResetScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.http2_rapid_reset import HTTP2RapidResetScanner

URL_HTTPS = "https://example.com"
URL_HTTP  = "http://example.com"


class TestHTTP2RapidReset(unittest.TestCase):
    def _make(self):
        s = HTTP2RapidResetScanner.__new__(HTTP2RapidResetScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = headers or {}
        return r

    # ── HTTP (plain) — skip ───────────────────────────────────────────────────

    def test_http_target_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp()
            results = s.scan(URL_HTTP)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        # No WARN for plain HTTP
        self.assertFalse(any(r["status"] == "WARN" for r in results))

    # ── Alt-svc h2 with affected server ──────────────────────────────────────

    def test_h2_on_old_nginx_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                headers={
                    "alt-svc": 'h2=":443"; ma=2592000',
                    "server": "nginx/1.18.0",
                }
            )
            results = s.scan(URL_HTTPS)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("rapid reset" in r["type"].lower() or "h2" in r["type"].lower() for r in warns))
        # Should mention CVE
        self.assertTrue(any("CVE" in r.get("detail", "") for r in warns))

    def test_h2_on_recent_nginx_warns_verify(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                headers={
                    "alt-svc": 'h2=":443"',
                    "server": "nginx/1.25.4",
                }
            )
            results = s.scan(URL_HTTPS)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("h2" in r["type"].lower() for r in warns))

    # ── Via header ────────────────────────────────────────────────────────────

    def test_via_h2_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                headers={
                    "via": "HTTP/2.0 proxy1",
                    "server": "Apache/2.4.50",
                }
            )
            results = s.scan(URL_HTTPS)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(len(warns) > 0)

    # ── gRPC endpoint ─────────────────────────────────────────────────────────

    def test_grpc_endpoint_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                headers={"content-type": "application/grpc"}
            )
            results = s.scan(URL_HTTPS)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("grpc" in r["type"].lower() for r in warns))

    # ── No H2 indicators ─────────────────────────────────────────────────────

    def test_no_h2_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                headers={"server": "Apache/2.4.58", "content-type": "text/html"}
            )
            results = s.scan(URL_HTTPS)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL_HTTPS)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
