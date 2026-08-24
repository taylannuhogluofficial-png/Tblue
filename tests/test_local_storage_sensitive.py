"""Tests for LocalStorageSensitiveScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.local_storage_sensitive import LocalStorageSensitiveScanner

URL = "https://example.com"


class TestLocalStorageSensitive(unittest.TestCase):
    def _make(self):
        s = LocalStorageSensitiveScanner.__new__(LocalStorageSensitiveScanner)
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

    # ── JWT token stored in localStorage fails ────────────────────────────────

    def test_jwt_in_localstorage_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(self._page("localStorage.setItem('jwt', response.token);"))
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("jwt" in r["type"].lower() or "token" in r["type"].lower() for r in fails))

    # ── Access token stored fails ─────────────────────────────────────────────

    def test_access_token_in_localstorage_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(self._page("localStorage.setItem('access_token', data.access_token);"))
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(len(fails) > 0)

    # ── Password stored fails ─────────────────────────────────────────────────

    def test_password_in_sessionstorage_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(self._page("sessionStorage.setItem('password', pwd);"))
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("password" in r["type"].lower() for r in fails))

    # ── CSRF token stored warns ───────────────────────────────────────────────

    def test_csrf_in_localstorage_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(self._page("localStorage.setItem('csrf', token);"))
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("csrf" in r["type"].lower() for r in warns))

    # ── API key stored fails ──────────────────────────────────────────────────

    def test_api_key_in_localstorage_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(self._page("localStorage.setItem('api_key', config.key);"))
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("api" in r["type"].lower() or "key" in r["type"].lower() for r in fails))

    # ── Non-sensitive keys pass ───────────────────────────────────────────────

    def test_non_sensitive_keys_pass(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(self._page(
                "localStorage.setItem('theme', 'dark'); localStorage.setItem('language', 'en');"
            ))
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── No storage usage passes ───────────────────────────────────────────────

    def test_no_storage_usage_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp("<html><body>Hello world</body></html>")
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── No response passes ────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
