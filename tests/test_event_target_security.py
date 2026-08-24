"""Tests for EventTargetSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.event_target_security import EventTargetSecurityScanner


def _scanner():
    s = EventTargetSecurityScanner.__new__(EventTargetSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_event_target_sensitive_custom_event():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const evt = new CustomEvent('auth', {detail: {token: userToken, secret: apiKey}})\n"
        "document.dispatchEvent(evt)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "event_target_sensitive_custom_event" in types


def test_event_target_global_surveillance():
    s = _scanner()
    s.http.get.return_value = _resp(
        "window.addEventListener('storage', (e) => {\n"
        "  analytics('storage_change', {key: e.key, value: e.newValue})\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "event_target_global_surveillance" in types


def test_event_target_dispatch_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const evt = new CustomEvent(searchParams.get('type'), {detail: {data: payload}})\n"
        "el.dispatchEvent(evt)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "event_target_dispatch_from_param" in types


def test_event_target_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No event dispatching or listeners</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "event_target_not_used"
    assert results[0]["status"] == "PASS"


def test_event_target_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "event_target_not_used"
