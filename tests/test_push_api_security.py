"""Tests for PushAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.push_api_security import PushAPISecurityScanner


def _scanner():
    s = PushAPISecurityScanner.__new__(PushAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestSilentPush:
    def test_silent_push_fails(self):
        s = _scanner()
        body = "registration.pushManager.subscribe({ userVisibleOnly: false, applicationServerKey: key })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "push_api_silent_push" in types


class TestMissingVapid:
    def test_no_vapid_warns(self):
        s = _scanner()
        body = "registration.pushManager.subscribe({ userVisibleOnly: true })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "push_api_missing_vapid" in types

    def test_with_vapid_passes(self):
        s = _scanner()
        body = "registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlB64ToUint8Array(vapidPublicKey) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "push_api_missing_vapid" not in types


class TestPayloadLogged:
    def test_push_data_logged_warns(self):
        s = _scanner()
        # _PUSH_LOG_DATA_RE: event.data before console.log (no ;); also need _PUSH_ANY_RE to match
        body = "registration.pushManager.getSubscription()\nself.addEventListener('push', event => { const t = event.data.text()\nconsole.log(t) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "push_api_data_logged" in types


class TestNotUsed:
    def test_no_push_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "push_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
