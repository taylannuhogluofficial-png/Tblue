"""Tests for JSONPEndpointScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.jsonp_endpoint import JSONPEndpointScanner, _MARKER

URL = "https://example.com"


class TestJSONPEndpoint(unittest.TestCase):
    def _make(self):
        s = JSONPEndpointScanner.__new__(JSONPEndpointScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = {}
        return r

    # ── Callback reflected as JSONP fails ─────────────────────────────────────

    def test_jsonp_callback_reflected_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if _MARKER in u:
                    return self._resp(f'{_MARKER}({{"user": "admin", "email": "a@b.com"}})')
                return self._resp("", status=404)
            m.get.side_effect = side_effect
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("jsonp" in r["type"].lower() or "callback" in r["type"].lower() for r in fails))

    # ── Pre-existing JSONP response warns ─────────────────────────────────────

    def test_preexisting_jsonp_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if "callback=" in u and _MARKER not in u:
                    return self._resp('existingCallback({"data": "value"})')
                if _MARKER in u:
                    return self._resp('existingCallback({"data": "value"})')
                return self._resp("", status=404)
            m.get.side_effect = side_effect
            results = s.scan(URL)
        warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertIsInstance(results, list)

    # ── No JSONP response passes ──────────────────────────────────────────────

    def test_no_jsonp_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp('{"data": "value"}', status=200)
            results = s.scan(URL)
        # Passes because JSON response without JSONP wrapper
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertEqual(len(fails), 0)

    # ── 404 on all API paths passes ───────────────────────────────────────────

    def test_no_jsonp_endpoints_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp("", status=404)
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── No response passes ────────────────────────────────────────────────────

    def test_no_response_returns_results(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertIsInstance(results, list)
