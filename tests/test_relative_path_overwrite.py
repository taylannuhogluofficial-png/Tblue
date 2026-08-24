"""Tests for RelativePathOverwriteScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.relative_path_overwrite import RelativePathOverwriteScanner

URL_RPO  = "https://example.com/app/page"    # no trailing slash, no extension
URL_SAFE = "https://example.com/app/page/"   # trailing slash — safe
URL_FILE = "https://example.com/index.html"  # extension — safe


def _mock_headers(d):
    m = MagicMock()
    m.items.return_value = list(d.items())
    return m


class TestRelativePathOverwrite(unittest.TestCase):
    def _make(self):
        s = RelativePathOverwriteScanner.__new__(RelativePathOverwriteScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", headers=None, status=200):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = _mock_headers(headers or {})
        return r

    # ── Ambiguous path + relative CSS + no nosniff warns ─────────────────────

    def test_relative_css_on_ambiguous_path_warns(self):
        body = '<html><head><link rel="stylesheet" href="styles.css"></head><body></body></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL_RPO)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("relative" in r["type"].lower() or "css" in r["type"].lower() or "overwrite" in r["type"].lower() for r in warns))

    # ── Ambiguous path + relative JS warns ───────────────────────────────────

    def test_relative_js_on_ambiguous_path_warns(self):
        body = '<html><head><script src="app.js"></script></head><body></body></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL_RPO)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(len(warns) > 0)

    # ── Missing X-Content-Type-Options nosniff ────────────────────────────────

    def test_no_nosniff_with_relative_resources_warns(self):
        body = '<html><head><link rel="stylesheet" href="app.css"></head></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body, headers={})
            results = s.scan(URL_RPO)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("nosniff" in r["type"].lower() or "content-type" in r["type"].lower() for r in warns))

    # ── Root-relative CSS is safe ─────────────────────────────────────────────

    def test_root_relative_css_passes(self):
        body = '<html><head><link rel="stylesheet" href="/static/styles.css"></head></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL_RPO)
        # Root-relative paths don't match the relative regex
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertEqual(len(fails), 0)

    # ── URL with trailing slash is safe ──────────────────────────────────────

    def test_trailing_slash_url_passes(self):
        body = '<html><head><link rel="stylesheet" href="styles.css"></head></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL_SAFE)
        # Trailing slash means no RPO risk
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── File extension URL is safe ────────────────────────────────────────────

    def test_file_extension_url_passes(self):
        body = '<html><head><link rel="stylesheet" href="style.css"></head></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL_FILE)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── No relative resources passes ─────────────────────────────────────────

    def test_no_relative_resources_passes(self):
        body = '<html><head><link rel="stylesheet" href="https://example.com/styles.css"></head></html>'
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL_RPO)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── No response passes ────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL_RPO)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
