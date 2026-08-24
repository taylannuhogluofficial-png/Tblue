"""Tests for WebhookSecurityScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.webhook_security import WebhookSecurityScanner

URL = "https://example.com"
URL_HTTP = "http://example.com"


class TestWebhookSecurity(unittest.TestCase):
    def _make(self):
        s = WebhookSecurityScanner.__new__(WebhookSecurityScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = headers or {}
        return r

    def _not_found(self):
        return self._resp("Not Found", 404)

    # ── HTTP target ───────────────────────────────────────────────────────────

    def test_http_target_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._not_found()
            results = s.scan(URL_HTTP)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("http" in r["type"].lower() or "https" in r["type"].lower() for r in warns))

    # ── Webhook GET returns 200 ───────────────────────────────────────────────

    def test_webhook_json_on_get_warns(self):
        def side(url, **kw):
            if "/webhook" in url:
                return self._resp(
                    '{"status":"waiting"}',
                    200,
                    {"content-type": "application/json"}
                )
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(len(warns) > 0)

    def test_webhook_body_text_on_get_warns(self):
        def side(url, **kw):
            if "/webhook" in url:
                return self._resp("webhook received and processed", 200)
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(len(warns_or_fails) > 0)

    # ── Webhook echoes payload ────────────────────────────────────────────────

    def test_webhook_echoes_payload_fails(self):
        payload_echo = '{"event":"push","payload":{"ref":"main"},"webhook_id":"abc123"}'

        def side(url, **kw):
            if "/webhook" in url:
                return self._resp(payload_echo, 200, {"content-type": "application/json"})
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("echo" in r["type"].lower() or "payload" in r["type"].lower() for r in fails))

    # ── Ngrok / debug interface ───────────────────────────────────────────────

    def test_ngrok_debug_interface_warns(self):
        ngrok_body = "<html>ngrok tunnel inspector - forward to localhost:3000</html>"

        def side(url, **kw):
            if "/webhook" in url:
                return self._resp(ngrok_body, 200)
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("debug" in r["type"].lower() or "tunnel" in r["type"].lower() or "ngrok" in r["type"].lower() for r in warns))

    # ── Debug path ────────────────────────────────────────────────────────────

    def test_webhook_debug_path_warns(self):
        def side(url, **kw):
            if "/webhook/test" in url or "/webhooks/debug" in url:
                return self._resp("<html>Webhook Test Console</html>", 200)
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("debug" in r["type"].lower() or "test" in r["type"].lower() for r in warns))

    # ── Clean target ──────────────────────────────────────────────────────────

    def test_all_404_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._not_found()
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── No response ────────────────────────────────────────────────────────────

    def test_exception_suppressed(self):
        def side(url, **kw):
            raise ConnectionError("refused")

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        self.assertFalse(any(r["status"] == "FAIL" for r in results))
