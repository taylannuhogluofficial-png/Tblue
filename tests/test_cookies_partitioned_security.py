"""Tests for CookiesPartitionedSecurityScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.cookies_partitioned_security import CookiesPartitionedSecurityScanner

URL = "https://example.com"


def _resp_with_cookie(cookie_value: str):
    r = MagicMock()
    r.status_code = 200
    r.text = ""
    r.headers = {"set-cookie": cookie_value}
    r.headers.get = lambda k, d="": {"set-cookie": cookie_value}.get(k, d)
    return r


class TestCookiesPartitionedSecurity(unittest.TestCase):
    def _make(self):
        s = CookiesPartitionedSecurityScanner.__new__(CookiesPartitionedSecurityScanner)
        s.http = MagicMock()
        return s

    def _resp(self, cookie=None, status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = ""
        all_headers = headers or {}
        if cookie:
            all_headers["set-cookie"] = cookie
        r.headers = all_headers
        return r

    # ── SameSite=None without Partitioned ─────────────────────────────────────

    def test_samesite_none_without_partitioned_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                cookie="session=abc123; SameSite=None; Secure; HttpOnly"
            )
            results = s.scan(URL)
        warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("partitioned" in r["type"].lower() or "samesite" in r["type"].lower() or "chips" in r["type"].lower() for r in warns_or_fails))

    # ── Partitioned without Secure ────────────────────────────────────────────

    def test_partitioned_without_secure_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                cookie="widget=xyz; SameSite=None; Partitioned"
            )
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("secure" in r["type"].lower() or "partitioned" in r["type"].lower() for r in fails))

    # ── Partitioned without SameSite=None ────────────────────────────────────

    def test_partitioned_without_samesite_none_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                cookie="widget=xyz; Secure; Partitioned"
            )
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("samesite" in r["type"].lower() or "partitioned" in r["type"].lower() for r in warns))

    # ── Properly configured CHIPS cookie ─────────────────────────────────────

    def test_valid_chips_cookie_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                cookie="session=abc; SameSite=None; Secure; Partitioned; HttpOnly"
            )
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── __Host- with Partitioned ──────────────────────────────────────────────

    def test_host_prefix_with_partitioned_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                cookie="__Host-session=abc; Secure; Partitioned; Path=/"
            )
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("__host-" in r["type"].lower() or "prefix" in r["type"].lower() for r in warns))

    # ── No Set-Cookie header ──────────────────────────────────────────────────

    def test_no_cookies_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp()
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── No response ────────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
