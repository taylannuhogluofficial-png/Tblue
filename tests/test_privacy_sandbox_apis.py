"""Tests for PrivacySandboxAPIsScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.privacy_sandbox_apis import PrivacySandboxAPIsScanner

URL = "https://example.com"


class TestPrivacySandboxAPIs(unittest.TestCase):
    def _make(self):
        s = PrivacySandboxAPIsScanner.__new__(PrivacySandboxAPIsScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = headers or {}
        return r

    # ── Topics API ────────────────────────────────────────────────────────────

    def test_observe_browsing_topics_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={"observe-browsing-topics": "?1"})
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("topics" in r["type"].lower() for r in warns))

    def test_browsing_topics_js_warns(self):
        body = "<script>const topics = await document.browsingTopics();</script>"
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("topics" in r["type"].lower() for r in warns))

    # ── Attribution Reporting ─────────────────────────────────────────────────

    def test_attribution_reporting_source_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "attribution-reporting-register-source": '{"destination":"https://shop.example"}'
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("attribution" in r["type"].lower() for r in warns))

    def test_attribution_reporting_trigger_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "attribution-reporting-register-trigger": '{"event_trigger_data":[{"trigger_data":"1"}]}'
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("attribution" in r["type"].lower() or "trigger" in r["type"].lower() for r in warns))

    # ── Shared Storage ────────────────────────────────────────────────────────

    def test_shared_storage_write_header_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "shared-storage-write": "set;key=campaignId;value=123"
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("shared" in r["type"].lower() or "storage" in r["type"].lower() for r in warns))

    def test_shared_storage_js_warns(self):
        body = "<script>await window.sharedStorage.set('key', 'value');</script>"
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("shared" in r["type"].lower() or "storage" in r["type"].lower() for r in warns))

    # ── Protected Audience (FLEDGE) ───────────────────────────────────────────

    def test_interest_group_join_js_warns(self):
        body = "<script>navigator.joinAdInterestGroup({owner: 'https://ad.example', name: 'cars'}, 86400);</script>"
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("interest" in r["type"].lower() or "fledge" in r["type"].lower() or "protected" in r["type"].lower() for r in warns))

    # ── Private State Tokens ──────────────────────────────────────────────────

    def test_private_state_token_header_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={
                "private-state-token": "token_blob_here"
            })
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("private" in r["type"].lower() or "state" in r["type"].lower() or "token" in r["type"].lower() for r in warns))

    # ── Clean page — no Privacy Sandbox ──────────────────────────────────────

    def test_no_privacy_sandbox_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body="<html><body>hello</body></html>")
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
