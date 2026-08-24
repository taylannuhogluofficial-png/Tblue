"""Tests for SharedStorageSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.shared_storage_security import SharedStorageSecurityScanner


def _scanner():
    s = SharedStorageSecurityScanner.__new__(SharedStorageSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestSensitiveWrite:
    def test_pii_written_to_shared_storage_fails(self):
        s = _scanner()
        body = "window.sharedStorage.set('userId', userData.email)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "shared_storage_sensitive_data_written" in types


class TestDataFromParam:
    def test_data_from_url_param_fails(self):
        s = _scanner()
        body = "window.sharedStorage.set('campaign', searchParams.get('utm_id'))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "shared_storage_data_from_url_param" in types


class TestReadExfil:
    def test_read_exfiltrated_fails(self):
        s = _scanner()
        body = "const val = await window.sharedStorage.get('segment')\nfetch('/collect', {body: val})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "shared_storage_read_exfiltrated" in types


class TestNotUsed:
    def test_no_shared_storage_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "shared_storage_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
