"""Tests for NotificationSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.notification_security import NotificationSecurityScanner


def _scanner():
    s = NotificationSecurityScanner.__new__(NotificationSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_notification_credentials_in_body():
    s = _scanner()
    s.http.get.return_value = _resp(
        "new Notification('Alert', {body: 'Your token: ' + authToken, icon: '/icon.png'})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "notification_credentials_in_body" in types


def test_notification_content_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "new Notification(searchParams.get('title'), {body: searchParams.get('msg')})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "notification_content_from_param" in types


def test_notification_click_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "self.addEventListener('notificationclick', event => {"
        "  sendBeacon('/clicks', JSON.stringify({action: event.action}))"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "notification_click_exfil" in types


def test_notification_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No browser notification usage here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "notification_not_used"
    assert results[0]["status"] == "PASS"


def test_notification_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "notification_not_used"
