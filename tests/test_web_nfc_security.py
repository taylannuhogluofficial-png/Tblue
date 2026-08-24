"""Tests for WebNFCSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.web_nfc_security import WebNFCSecurityScanner


def _scanner():
    s = WebNFCSecurityScanner.__new__(WebNFCSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestAutoScan:
    def test_auto_scan_on_load_fails(self):
        s = _scanner()
        body = "window.addEventListener('load', async () => { const reader = new NDEFReader(); await reader.scan(); })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_nfc_auto_scan" in types


class TestWriteFromURLParam:
    def test_write_from_url_param_fails(self):
        s = _scanner()
        # _NFC_WRITE_URL_RE: .write([^)]*searchParams within same group (no ) before searchParams)
        body = "const reader = new NDEFReader(); reader.write(searchParams.get('payload'))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_nfc_write_from_url_param" in types


class TestDataTransmitted:
    def test_nfc_data_sent_warns(self):
        s = _scanner()
        body = "const reader = new NDEFReader()\nconst records = message.records\nfetch('/log', {body: JSON.stringify(records)})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_nfc_data_transmitted" in types


class TestNotUsed:
    def test_no_nfc_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "web_nfc_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
