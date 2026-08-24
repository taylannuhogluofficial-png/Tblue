"""Tests for CompressionOracleScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.compression_oracle import CompressionOracleScanner

URL_HTTPS = "https://example.com"
URL_HTTP  = "http://example.com"

_CSRF_IN_BODY = (
    '<html><body>'
    '<input type="hidden" name="csrf" value="abc123xyz456def789ghi012">'
    '</body></html>'
)
_NO_CSRF_BODY = "<html><body><p>Hello world</p></body></html>"
_JSON_API_BODY = '{"users": [{"id": 1, "name": "Alice"}]}'


class TestCompressionOracle(unittest.TestCase):
    def _make(self):
        s = CompressionOracleScanner.__new__(CompressionOracleScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = headers or {}
        return r

    # ── HTTP target is safe ───────────────────────────────────────────────────

    def test_http_target_not_vulnerable(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=_CSRF_IN_BODY, headers={"content-encoding": "gzip"})
            results = s.scan(URL_HTTP)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── No compression — safe ─────────────────────────────────────────────────

    def test_no_compression_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=_CSRF_IN_BODY, headers={})
            results = s.scan(URL_HTTPS)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── BREACH conditions met ─────────────────────────────────────────────────

    def test_gzip_with_csrf_token_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                body=_CSRF_IN_BODY,
                headers={"content-encoding": "gzip", "content-type": "text/html"}
            )
            results = s.scan(URL_HTTPS)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("breach" in r["type"].lower() or "csrf" in r["type"].lower() or "compression" in r["type"].lower() for r in fails))

    def test_br_compression_with_csrf_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                body=_CSRF_IN_BODY,
                headers={"content-encoding": "br", "content-type": "text/html"}
            )
            results = s.scan(URL_HTTPS)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(len(fails) > 0)

    # ── Compression without detected secrets ─────────────────────────────────

    def test_gzip_without_secrets_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                body=_NO_CSRF_BODY,
                headers={"content-encoding": "gzip", "content-type": "text/html"}
            )
            results = s.scan(URL_HTTPS)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("compression" in r["type"].lower() for r in warns))

    # ── JSON API with compression — lower risk ────────────────────────────────

    def test_gzip_on_json_api_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                body=_JSON_API_BODY,
                headers={
                    "content-encoding": "gzip",
                    "content-type": "application/json"
                }
            )
            results = s.scan(URL_HTTPS)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── Session token in body ────────────────────────────────────────────────

    def test_gzip_with_session_in_body_fails(self):
        body = '{"sessionId": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"}'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                body=body,
                headers={"content-encoding": "gzip", "content-type": "text/html"}
            )
            results = s.scan(URL_HTTPS)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(len(fails) > 0)

    # ── No response ────────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL_HTTPS)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
