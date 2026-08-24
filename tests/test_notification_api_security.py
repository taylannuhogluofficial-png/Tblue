"""Tests for NotificationAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.notification_api_security import NotificationAPISecurityScanner


def _scanner():
    s = NotificationAPISecurityScanner.__new__(NotificationAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestAutoPermissionRequest:
    def test_request_on_load_warns(self):
        s = _scanner()
        body = "window.addEventListener('load', () => { Notification.requestPermission() })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "notification_auto_permission_request" in types


class TestSensitiveBody:
    def test_token_in_notification_fails(self):
        s = _scanner()
        body = "new Notification('Alert', {body: 'Your token: ' + userToken})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "notification_sensitive_body_content" in types


class TestFromURLParam:
    def test_notification_from_url_param_fails(self):
        s = _scanner()
        # _NOTIF_URL_PARAM_RE: new Notification([^)]*searchParams — no ) before searchParams
        body = "new Notification(searchParams.get('title'))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "notification_content_from_url_param" in types


class TestNotUsed:
    def test_no_notification_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "notification_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
