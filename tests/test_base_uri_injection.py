"""Tests for BaseURIInjectionScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.base_uri_injection import BaseURIInjectionScanner

URL_HTTPS = "https://example.com"


def _mock_headers(d):
    m = MagicMock()
    m.items.return_value = list(d.items())
    return m


class TestBaseURIInjection(unittest.TestCase):
    def _make(self):
        s = BaseURIInjectionScanner.__new__(BaseURIInjectionScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", headers=None):
        r = MagicMock()
        r.status_code = 200
        r.text = body
        r.headers = _mock_headers(headers or {})
        return r

    # ── CSP with script-src but no base-uri ───────────────────────────────────

    def test_csp_missing_base_uri_with_script_src_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                headers={"Content-Security-Policy": "script-src 'self'"}
            )
            results = s.scan(URL_HTTPS)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("base-uri" in r["type"].lower() or "base_uri" in r["type"].lower() or "base uri" in r["type"].lower() for r in fails))

    # ── CSP with base-uri wildcard ────────────────────────────────────────────

    def test_base_uri_wildcard_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                headers={"Content-Security-Policy": "base-uri *; script-src 'self'"}
            )
            results = s.scan(URL_HTTPS)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("wildcard" in r["type"].lower() or "base-uri" in r["type"].lower() for r in fails))

    # ── CSP missing entirely but has base-uri WARN ────────────────────────────

    def test_csp_present_but_no_base_uri_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                headers={"Content-Security-Policy": "default-src 'self'"}
            )
            results = s.scan(URL_HTTPS)
        warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("base" in r["type"].lower() for r in warns_or_fails))

    # ── Multiple base tags ────────────────────────────────────────────────────

    def test_multiple_base_tags_warns(self):
        body = '<html><head><base href="/"><base href="/alt/"></head><body></body></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                body=body,
                headers={"Content-Security-Policy": "base-uri 'self'"}
            )
            results = s.scan(URL_HTTPS)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("multiple" in r["type"].lower() or "2" in r["type"] for r in warns))

    # ── <base> with HTTP href on HTTPS page ───────────────────────────────────

    def test_http_base_on_https_fails(self):
        body = '<html><head><base href="http://example.com/"></head><body></body></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                body=body,
                headers={"Content-Security-Policy": "base-uri 'self'"}
            )
            results = s.scan(URL_HTTPS)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("http" in r["type"].lower() for r in fails))

    # ── <base> pointing to external origin ───────────────────────────────────

    def test_external_base_href_warns(self):
        body = '<html><head><base href="https://evil.com/"></head><body></body></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                body=body,
                headers={"Content-Security-Policy": "base-uri 'self'"}
            )
            results = s.scan(URL_HTTPS)
        warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("external" in r["type"].lower() for r in warns_or_fails))

    # ── Good CSP with base-uri 'self' and no base tags ────────────────────────

    def test_base_uri_self_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                body="<html><body>content</body></html>",
                headers={"Content-Security-Policy": "script-src 'self'; base-uri 'self'"}
            )
            results = s.scan(URL_HTTPS)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── No response ───────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL_HTTPS)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
