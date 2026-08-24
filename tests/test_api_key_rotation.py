"""Tests for APIKeyRotationScanner."""
import time
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.api_key_rotation import APIKeyRotationScanner

URL = "https://example.com"


def _mock_headers(items=None):
    """Return a MagicMock that behaves like a headers dict."""
    h = MagicMock()
    h.items.return_value = items or []
    h.__iter__ = lambda self: iter(dict(items or []))
    h.get = lambda k, d=None: dict(items or {}).get(k, d)
    return h


class TestAPIKeyRotation(unittest.TestCase):
    def _make(self):
        s = APIKeyRotationScanner.__new__(APIKeyRotationScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, header_items=None):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = _mock_headers(header_items)
        return r

    def _make_jwt(self, payload: dict) -> str:
        import base64, json
        header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
        pay    = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        sig    = base64.urlsafe_b64encode(b"fakesig").rstrip(b"=").decode()
        return f"{header}.{pay}.{sig}"

    # ── JWT expiry ────────────────────────────────────────────────────────────

    def test_jwt_no_exp_warns(self):
        now = int(time.time())
        token = self._make_jwt({"sub": "user1", "iat": now})
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(f"token: {token}")
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("exp" in r["type"].lower() or "missing" in r["type"].lower() for r in warns))

    def test_jwt_long_lived_warns(self):
        now = int(time.time())
        token = self._make_jwt({"sub": "user1", "iat": now, "exp": now + 200 * 86400})
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(f"token: {token}")
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("200" in r["type"] or "day" in r["type"].lower() for r in warns))

    def test_short_lived_jwt_passes(self):
        now = int(time.time())
        token = self._make_jwt({"sub": "user1", "iat": now, "exp": now + 3600})
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(f"token: {token}")
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── Cloud keys ────────────────────────────────────────────────────────────

    def test_aws_key_in_response_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp('var key = "AKIAIOSFODNN7EXAMPLE";')
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("aws" in r["type"].lower() for r in fails))

    def test_gcp_key_in_response_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp('apiKey: "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQE"')
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("gcp" in r["type"].lower() for r in fails))

    # ── Basic auth in JS ──────────────────────────────────────────────────────

    def test_basic_auth_in_js_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp('Authorization: "Basic " + btoa("admin:secret123")')
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("basic" in r["type"].lower() or "auth" in r["type"].lower() for r in fails))

    # ── Long-lived cookies ────────────────────────────────────────────────────

    def test_far_future_cookie_warns(self):
        cookie_val = "session=abc; Expires=Fri, 01 Jan 2038 00:00:00 GMT; HttpOnly"
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                "<html>ok</html>",
                header_items=[("Set-Cookie", cookie_val)]
            )
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("cookie" in r["type"].lower() or "expir" in r["type"].lower() for r in warns))

    # ── Clean page ────────────────────────────────────────────────────────────

    def test_clean_page_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp("<html><body>Hello world</body></html>")
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))
