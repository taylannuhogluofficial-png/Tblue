"""Tests for ReDoSPassiveScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.redos_passive import ReDoSPassiveScanner

URL = "https://example.com"


class TestReDoSPassive(unittest.TestCase):
    def _make(self):
        s = ReDoSPassiveScanner.__new__(ReDoSPassiveScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = {}
        return r

    # ── Regex timeout in response ─────────────────────────────────────────────

    def test_regex_timeout_in_response_warns(self):
        body = 'Internal Server Error: regex timeout — pattern too complex'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("regex" in r["type"].lower() or "redos" in r["type"].lower() for r in warns))

    def test_regex_catastrophic_in_response_warns(self):
        body = 'Error: regular expression catastrophic backtracking detected'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(len(warns) > 0)

    # ── Nested quantifier in body ─────────────────────────────────────────────

    def test_nested_quantifier_in_body_warns(self):
        body = r'<script>var re = /([a-z]+)+/;</script>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("quantifier" in r["type"].lower() or "redos" in r["type"].lower() or "nested" in r["type"].lower() for r in warns))

    # ── Dynamic RegExp in body ────────────────────────────────────────────────

    def test_dynamic_regexp_in_body_warns(self):
        body = r'<script>var re = new RegExp(req.params.search);</script>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("dynamic" in r["type"].lower() or "regexp" in r["type"].lower() for r in warns))

    # ── JS bundle scanning ────────────────────────────────────────────────────

    def test_nested_quantifier_in_js_bundle_warns(self):
        page_body = '<html><script src="/bundle.js"></script></html>'
        js_body = r'var emailRe = /([a-z0-9._]+)+@/;'

        def side(url, **kw):
            if url == URL:
                return self._resp(page_body)
            if "bundle.js" in url:
                return self._resp(js_body)
            return self._resp("", 404)

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(len(warns) > 0)

    # ── Clean page ────────────────────────────────────────────────────────────

    def test_clean_page_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp("<html><body>Hello</body></html>")
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
