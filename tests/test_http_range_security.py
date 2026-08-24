"""Tests for HTTPRangeSecurityScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.http_range_security import HTTPRangeSecurityScanner

URL = "https://example.com"
API_URL = "https://example.com/api/v1/users"
AUTH_URL = "https://example.com/login"
CONFIG_URL = "https://example.com/config.json"


class TestHTTPRangeSecurity(unittest.TestCase):
    def _make(self):
        s = HTTPRangeSecurityScanner.__new__(HTTPRangeSecurityScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = headers or {}
        return r

    # ── Accept-Ranges on API endpoint ─────────────────────────────────────────

    def test_accept_ranges_on_api_endpoint_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                '{"users":[]}',
                200,
                {"accept-ranges": "bytes", "content-type": "application/json"}
            )
            results = s.scan(API_URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("api" in r["type"].lower() or "json" in r["type"].lower() or "accept-ranges" in r["type"].lower() for r in warns))

    def test_accept_ranges_on_json_content_type_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                '{"ok":true}',
                200,
                {"accept-ranges": "bytes", "content-type": "application/json; charset=utf-8"}
            )
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(len(warns) > 0)

    # ── Accept-Ranges on auth path ─────────────────────────────────────────────

    def test_accept_ranges_on_auth_path_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                "<form>login</form>",
                200,
                {"accept-ranges": "bytes"}
            )
            results = s.scan(AUTH_URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("auth" in r["type"].lower() or "auth path" in r["type"].lower() for r in warns))

    # ── Accept-Ranges on sensitive file ───────────────────────────────────────

    def test_accept_ranges_on_config_json_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                '{"db_url":"postgres://..."}',
                200,
                {"accept-ranges": "bytes"}
            )
            results = s.scan(CONFIG_URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("sensitive" in r["type"].lower() or "config" in r["type"].lower() or "file" in r["type"].lower() for r in fails))

    # ── Accept-Ranges: none — safe ────────────────────────────────────────────

    def test_accept_ranges_none_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                '{"users":[]}',
                200,
                {"accept-ranges": "none", "content-type": "application/json"}
            )
            results = s.scan(API_URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── 206 Partial Content from auth endpoint ────────────────────────────────

    def test_206_from_auth_path_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                "partial content",
                206,
                {"content-range": "bytes 0-100/500"}
            )
            results = s.scan(AUTH_URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("206" in r["type"] or "partial" in r["type"].lower() or "auth" in r["type"].lower() for r in warns))

    # ── Content-Range reveals file size ───────────────────────────────────────

    def test_content_range_reveals_size_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                "partial",
                206,
                {"content-range": "bytes 0-0/98765"}
            )
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("size" in r["type"].lower() or "content-range" in r["type"].lower() for r in warns))

    # ── Multipart byteranges ──────────────────────────────────────────────────

    def test_multipart_byteranges_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                "--boundary\r\nContent-Type: text/html\r\n\r\npart1",
                206,
                {"content-type": "multipart/byteranges; boundary=boundary"}
            )
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("multipart" in r["type"].lower() or "byterange" in r["type"].lower() for r in warns))

    # ── Normal page without range support ────────────────────────────────────

    def test_no_accept_ranges_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp("<html>hello</html>", 200, {})
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── No response ────────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
