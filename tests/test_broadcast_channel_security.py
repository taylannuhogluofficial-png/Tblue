"""Tests for BroadcastChannel Security scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestBroadcastChannelSecurityScanner:
    def _scanner(self):
        from tblue.scanner.broadcast_channel_security import BroadcastChannelSecurityScanner
        return BroadcastChannelSecurityScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_broadcast_channel_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("var x = 1;")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_auth_channel_name_warns(self):
        s = self._scanner()
        body = "const bc = new BroadcastChannel('auth');"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("auth" in r["type"].lower() or "channel" in r["type"].lower() for r in warns)

    def test_session_channel_name_warns(self):
        s = self._scanner()
        body = 'const bc = new BroadcastChannel("session");'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("channel" in r["type"].lower() for r in warns)

    def test_sensitive_postmessage_warns(self):
        s = self._scanner()
        body = 'new BroadcastChannel("updates"); bc.postMessage({ token: authToken, session: id });'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("sensitive" in r["type"].lower() or "postmessage" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_scan_body_auth_channel(self):
        from tblue.scanner.broadcast_channel_security import _scan_body
        body = "const bc = new BroadcastChannel('auth');"
        findings = _scan_body(body, URL)
        assert any("auth" in f["type"].lower() for f in findings)

    def test_scan_body_no_channel(self):
        from tblue.scanner.broadcast_channel_security import _scan_body
        findings = _scan_body("var x = 1;", URL)
        assert findings == []

    def test_scan_body_safe_channel_name(self):
        from tblue.scanner.broadcast_channel_security import _scan_body
        body = "const bc = new BroadcastChannel('ui-updates');"
        findings = _scan_body(body, URL)
        # Non-auth channel name should not trigger auth warning
        assert not any("auth-state" in f["type"] for f in findings)

    def test_scan_body_sensitive_postmessage(self):
        from tblue.scanner.broadcast_channel_security import _scan_body
        body = 'new BroadcastChannel("x"); bc.postMessage({ token: t, key: k });'
        findings = _scan_body(body, URL)
        assert any("sensitive" in f["type"].lower() for f in findings)
