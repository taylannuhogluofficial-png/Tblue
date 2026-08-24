"""Tests for ClientSideRedirectScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.client_side_redirect import ClientSideRedirectScanner

URL = "https://example.com"


class TestClientSideRedirect(unittest.TestCase):
    def _make(self):
        s = ClientSideRedirectScanner.__new__(ClientSideRedirectScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body=""):
        r = MagicMock()
        r.status_code = 200
        r.text = body
        r.headers = {}
        return r

    def _page(self, js):
        return f"<html><body><script>{js}</script></body></html>"

    # ── location from URLSearchParams ─────────────────────────────────────────

    def test_location_from_search_params_warns(self):
        body = self._page("window.location = new URLSearchParams(window.location.search).get('next');")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("location" in r["type"].lower() or "redirect" in r["type"].lower() for r in warns))

    # ── location from hash ────────────────────────────────────────────────────

    def test_location_from_hash_warns(self):
        body = self._page("window.location.href = window.location.hash.slice(1);")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("hash" in r["type"].lower() or "fragment" in r["type"].lower() for r in warns))

    # ── location from referrer ────────────────────────────────────────────────

    def test_location_from_referrer_warns(self):
        body = self._page("window.location = document.referrer;")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("referrer" in r["type"].lower() for r in warns))

    # ── postMessage triggered redirect fails ──────────────────────────────────

    def test_postmessage_redirect_fails(self):
        body = self._page("""
window.addEventListener('message', function(event) {
    location.href = event.data.url;
});
        """)
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("postmessage" in r["type"].lower() or "message" in r["type"].lower() for r in fails))

    # ── eval with location fails ──────────────────────────────────────────────

    def test_eval_with_location_fails(self):
        body = self._page("eval(\"window.location='\" + param + \"'\");")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("eval" in r["type"].lower() for r in fails))

    # ── meta refresh to external warns ───────────────────────────────────────

    def test_meta_refresh_external_warns(self):
        body = '<html><head><meta http-equiv="refresh" content="0; url=https://evil.com"></head></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("meta" in r["type"].lower() or "refresh" in r["type"].lower() for r in warns))

    # ── prefix-only validation warns ──────────────────────────────────────────

    def test_prefix_only_validation_warns(self):
        body = self._page("""
var next = getParam('next');
if (next.startsWith('https://example.com')) {
    window.location = next;
}
        """)
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("prefix" in r["type"].lower() or "bypass" in r["type"].lower() or "validation" in r["type"].lower() for r in warns))

    # ── Safe page passes ──────────────────────────────────────────────────────

    def test_safe_page_passes(self):
        body = "<html><body><a href='/dashboard'>Go to dashboard</a></body></html>"
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── No response passes ────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
