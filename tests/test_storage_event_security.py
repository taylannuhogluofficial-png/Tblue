"""Tests for StorageEventSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.storage_event_security import StorageEventSecurityScanner


def _scanner():
    s = StorageEventSecurityScanner.__new__(StorageEventSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_storage_event_getitem_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const session = localStorage.getItem('session')\n"
        "fetch('/collect', {body: session})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "storage_event_getitem_exfil" in types


def test_storage_event_sensitive_data_stored():
    s = _scanner()
    s.http.get.return_value = _resp(
        "localStorage.setItem('auth_token', userToken)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "storage_event_sensitive_data_stored" in types


def test_storage_event_cross_tab_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "window.addEventListener('storage', (e) => {\n"
        "  sendBeacon('/track', JSON.stringify({key: e.key, value: e.newValue}))\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "storage_event_cross_tab_exfil" in types


def test_storage_event_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No browser data persistence</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "storage_event_not_used"
    assert results[0]["status"] == "PASS"


def test_storage_event_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "storage_event_not_used"
