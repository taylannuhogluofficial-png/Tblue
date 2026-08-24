"""Tests for StorageAccessAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.storage_access_api_security import StorageAccessAPISecurityScanner


def _scanner():
    s = StorageAccessAPISecurityScanner.__new__(StorageAccessAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_storage_access_cross_site_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.requestStorageAccess().then(() => {\n"
        "  const cookie = document.cookie\n"
        "  const local = localStorage.getItem('token')\n"
        "  fetch('/exfil', {body: JSON.stringify({cookie, local})})\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "storage_access_cross_site_exfil" in types


def test_storage_access_auto_requested_on_load():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.addEventListener('DOMContentLoaded', () => {\n"
        "  document.requestStorageAccess()\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "storage_access_auto_requested_on_load" in types


def test_storage_access_presence_tracking():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.hasStorageAccess().then(has => {\n"
        "  sendBeacon('/track', JSON.stringify({has}))\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "storage_access_presence_tracking" in types


def test_storage_access_api_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No storage access</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "storage_access_api_not_used"
    assert results[0]["status"] == "PASS"


def test_storage_access_api_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "storage_access_api_not_used"
