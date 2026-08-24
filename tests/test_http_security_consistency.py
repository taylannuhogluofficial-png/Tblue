"""Tests for HTTPSecurityConsistencyScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.http_security_consistency import HTTPSecurityConsistencyScanner

URL = "https://example.com"


def _mock_headers(d):
    m = MagicMock()
    m.items.return_value = list(d.items())
    return m


class TestHTTPSecurityConsistency(unittest.TestCase):
    def _make(self):
        s = HTTPSecurityConsistencyScanner.__new__(HTTPSecurityConsistencyScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = _mock_headers(headers or {})
        return r

    # ── CSP on main page absent on /api/ path warns ───────────────────────────

    def test_csp_absent_on_api_warns(self):
        main_headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
        }
        sub_headers = {}  # no CSP or XFO on sub-paths
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if u == URL:
                    return self._resp(body="<html>main</html>", headers=main_headers)
                return self._resp(body='{"ok": true}', status=200, headers=sub_headers)
            m.get.side_effect = side_effect
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(len(warns) > 0)
        self.assertTrue(any("csp" in r["type"].lower() or "x-frame" in r["type"].lower() or "absent" in r["type"].lower() for r in warns))

    # ── Consistent headers pass ───────────────────────────────────────────────

    def test_consistent_headers_pass(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
        }
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body="<html>ok</html>", headers=headers)
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── No security headers — no inconsistency to report ─────────────────────

    def test_no_baseline_headers_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body="<html>ok</html>", headers={})
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── No response ───────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
