"""Tests for ProtocolConfusionScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.protocol_confusion import ProtocolConfusionScanner

URL_HTTPS = "https://example.com"


def _mock_headers(d):
    m = MagicMock()
    m.items.return_value = list(d.items())
    return m


class TestProtocolConfusion(unittest.TestCase):
    def _make(self):
        s = ProtocolConfusionScanner.__new__(ProtocolConfusionScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = headers or {}
        return r

    # ── HTTP returns 200 (not redirecting) fails ──────────────────────────────

    def test_http_200_not_redirected_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                return self._resp(body="<html>content</html>", status=200)
            m.get.side_effect = side_effect
            results = s.scan(URL_HTTPS)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("http" in r["type"].lower() or "redirect" in r["type"].lower() for r in fails))

    # ── HTTP redirects to HTTP (not HTTPS) warns ──────────────────────────────

    def test_http_redirects_to_http_warns(self):
        http_resp = self._resp(body="", status=302, headers={"location": "http://example.com/home"})
        https_resp = self._resp(body="<html>secure</html>", status=200)
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if u.startswith("http://"):
                    return http_resp
                return https_resp
            m.get.side_effect = side_effect
            results = s.scan(URL_HTTPS)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("http" in r["type"].lower() for r in warns))

    # ── HTTP redirects to HTTPS but no HSTS warns ─────────────────────────────

    def test_http_to_https_no_hsts_warns(self):
        http_resp = self._resp(body="", status=301, headers={"location": "https://example.com/"})
        https_resp = self._resp(body="<html>secure</html>", status=200, headers={})
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if u.startswith("http://"):
                    return http_resp
                return https_resp
            m.get.side_effect = side_effect
            results = s.scan(URL_HTTPS)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("hsts" in r["type"].lower() or "transport" in r["type"].lower() for r in warns))

    # ── CSP without upgrade-insecure-requests warns ────────────────────────────

    def test_csp_without_upgrade_insecure_warns(self):
        http_resp = self._resp(body="", status=301, headers={"location": "https://example.com/"})
        https_resp = self._resp(
            body="<html>secure</html>",
            status=200,
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
            }
        )
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if u.startswith("http://"):
                    return http_resp
                return https_resp
            m.get.side_effect = side_effect
            results = s.scan(URL_HTTPS)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("upgrade" in r["type"].lower() or "insecure" in r["type"].lower() for r in warns))

    # ── Well-configured site passes ───────────────────────────────────────────

    def test_well_configured_passes(self):
        http_resp = self._resp(body="", status=301, headers={"location": "https://example.com/"})
        https_resp = self._resp(
            body="<html>secure</html>",
            status=200,
            headers={
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'; upgrade-insecure-requests",
            }
        )
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if u.startswith("http://"):
                    return http_resp
                return https_resp
            m.get.side_effect = side_effect
            results = s.scan(URL_HTTPS)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── No response passes ────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL_HTTPS)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
