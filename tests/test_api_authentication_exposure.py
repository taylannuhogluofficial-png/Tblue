"""Tests for APIAuthenticationExposureScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.api_authentication_exposure import APIAuthenticationExposureScanner

URL = "https://example.com"


class TestAPIAuthenticationExposure(unittest.TestCase):
    def _make(self):
        s = APIAuthenticationExposureScanner.__new__(APIAuthenticationExposureScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, ct="application/json"):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = {"content-type": ct}
        return r

    # ── API docs exposed warns ────────────────────────────────────────────────

    def test_swagger_exposed_warns(self):
        swagger = '{"openapi": "3.0.0", "paths": {"/api/users": {"get": {}}}}'
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if "/swagger" in u or "/api-docs" in u or "openapi" in u:
                    return self._resp(swagger)
                return self._resp("", status=404)
            m.get.side_effect = side_effect
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("doc" in r["type"].lower() or "swagger" in r["type"].lower() or "api" in r["type"].lower() for r in warns))

    # ── Sensitive API endpoint with data fails ────────────────────────────────

    def test_sensitive_api_accessible_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if "/api/users" in u or "/api/admin" in u:
                    return self._resp(
                        '{"users": [{"email": "admin@example.com", "role": "admin"}]}'
                    )
                return self._resp("", status=401)
            m.get.side_effect = side_effect
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("sensitive" in r["type"].lower() or "auth" in r["type"].lower() or "api" in r["type"].lower() for r in fails))

    # ── All API paths return 401 passes ───────────────────────────────────────

    def test_api_requires_auth_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp("Unauthorized", status=401)
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── All paths return 404 passes ───────────────────────────────────────────

    def test_all_404_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp("Not Found", status=404)
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── Non-JSON response on API path not flagged ─────────────────────────────

    def test_html_response_on_api_not_flagged(self):
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if "/api/" in u:
                    return self._resp("<html>Login required</html>", ct="text/html")
                return self._resp("", status=404)
            m.get.side_effect = side_effect
            results = s.scan(URL)
        # HTML responses (login redirects) should not be flagged as sensitive
        fails = [r for r in results if r["status"] == "FAIL" and "sensitive api" in r["type"].lower()]
        self.assertEqual(len(fails), 0)
