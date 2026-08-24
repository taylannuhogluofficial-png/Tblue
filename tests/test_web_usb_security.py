"""Tests for WebUSBSecurityScanner."""
import pytest
from unittest.mock import MagicMock
from tblue.scanner.web_usb_security import WebUSBSecurityScanner


def _scanner():
    s = WebUSBSecurityScanner.__new__(WebUSBSecurityScanner)
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
        body = "navigator.usb.requestDevice({ filters: [] });"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_usb_empty_filters" in types


class TestEnumerateDevices:
    def test_get_all_devices_warns(self):
        s = _scanner()
        body = """
        const devices = await navigator.usb.getDevices();
        devices.forEach(d => console.log(d.productName));
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_usb_enumerate_all_devices" in types


class TestDeviceInfoTransmitted:
    def test_device_info_sent_warns(self):
        s = _scanner()
        body = """
        const device = await navigator.usb.requestDevice({filters: [{vendorId: 0x1234}]});
        fetch('/track', {body: JSON.stringify({vid: device.vendorId, pid: device.productId})});
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_usb_device_info_transmitted" in types


class TestFirmwareWrite:
    def test_firmware_write_fails(self):
        s = _scanner()
        body = """
        const device = await navigator.usb.requestDevice({filters: [{vendorId: 0x1234}]});
        await device.transferOut(1, firmwareData);
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_usb_firmware_write" in types


class TestNotUsed:
    def test_no_usb_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "web_usb_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
