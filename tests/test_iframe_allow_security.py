"""Tests for IframeAllowSecurityScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.iframe_allow_security import IframeAllowSecurityScanner

URL = "https://example.com"


class TestIframeAllowSecurity(unittest.TestCase):
    def _make(self):
        s = IframeAllowSecurityScanner.__new__(IframeAllowSecurityScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body=""):
        r = MagicMock()
        r.status_code = 200
        r.text = body
        r.headers = {}
        return r

    # ── No iframes ────────────────────────────────────────────────────────────

    def test_no_iframes_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp("<html><body>Hello</body></html>")
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── allow="*" fails ───────────────────────────────────────────────────────

    def test_iframe_allow_wildcard_fails(self):
        body = '<html><body><iframe src="https://ads.example.com" allow="*"></iframe></body></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("wildcard" in r["type"].lower() or "*" in r["type"] for r in fails))

    # ── allow="camera" fails ──────────────────────────────────────────────────

    def test_iframe_allow_camera_fails(self):
        body = '<html><body><iframe src="https://widget.evil.com" allow="camera microphone"></iframe></body></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("camera" in r["type"].lower() or "microphone" in r["type"].lower() for r in fails))

    # ── allow="payment" fails ─────────────────────────────────────────────────

    def test_iframe_allow_payment_fails(self):
        body = '<html><body><iframe src="https://checkout.example.com" allow="payment"></iframe></body></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("payment" in r["type"].lower() for r in fails))

    # ── Cross-origin without sandbox warns ────────────────────────────────────

    def test_cross_origin_iframe_without_sandbox_warns(self):
        body = '<html><body><iframe src="https://widget.external.com/embed"></iframe></body></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("sandbox" in r["type"].lower() or "cross-origin" in r["type"].lower() for r in warns))

    # ── Sandbox allow-scripts + allow-same-origin broken ─────────────────────

    def test_sandbox_broken_by_scripts_and_same_origin_fails(self):
        body = '<html><body><iframe src="https://evil.com" sandbox="allow-scripts allow-same-origin"></iframe></body></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("sandbox" in r["type"].lower() or "broken" in r["type"].lower() for r in fails))

    # ── Safe same-origin iframe with allow="geolocation" passes at WARN level

    def test_same_origin_iframe_with_geolocation_warns(self):
        body = '<html><body><iframe src="/maps/embed" allow="geolocation"></iframe></body></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        # geolocation is WARN-level, not FAIL
        self.assertFalse(any(r["status"] == "FAIL" and "geolocation" in r["type"].lower() for r in results))

    # ── No response ───────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
