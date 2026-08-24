"""Tests for HIDAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.hid_api_security import HIDAPISecurityScanner


def _scanner():
    s = HIDAPISecurityScanner.__new__(HIDAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestEmptyFilters:
    def test_empty_filters_warns(self):
        s = _scanner()
        body = "const devices = await navigator.hid.requestDevice({filters: []})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "hid_empty_device_filters" in types


class TestDeviceEnumeration:
    def test_get_all_devices_warns(self):
        s = _scanner()
        body = "const devices = await navigator.hid.getDevices()"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "hid_device_enumeration" in types


class TestWriteFromURLParam:
    def test_hid_write_from_url_param_fails(self):
        s = _scanner()
        # _HID_WRITE_URL_RE: sendReport([^)]*searchParams — searchParams before first )
        body = "device.sendReport(0x00, new Uint8Array(searchParams.get('cmd').split(',')))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "hid_write_from_url_param" in types


class TestDeviceInfoTransmitted:
    def test_product_id_sent_warns(self):
        s = _scanner()
        # _HID_DEVICE_SEND_RE: productId before fetch within 200 non-semicolon chars
        body = "const devices = await navigator.hid.getDevices()\nconst productId = devices[0].productId\nfetch('/log', {body: productId})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "hid_device_info_transmitted" in types


class TestNotUsed:
    def test_no_hid_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "hid_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
