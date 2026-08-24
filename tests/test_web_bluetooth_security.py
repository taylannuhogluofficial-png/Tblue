"""Tests for WebBluetoothSecurityScanner."""
import pytest
from unittest.mock import MagicMock
from tblue.scanner.web_bluetooth_security import WebBluetoothSecurityScanner


def _scanner():
    s = WebBluetoothSecurityScanner.__new__(WebBluetoothSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestAcceptAllDevices:
    def test_accept_all_devices_warns(self):
        s = _scanner()
        body = "const device = await navigator.bluetooth.requestDevice({ acceptAllDevices: true });"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_bluetooth_accept_all_devices" in types


class TestPairedEnumeration:
    def test_get_devices_warns(self):
        s = _scanner()
        body = "const devices = await navigator.bluetooth.getDevices();"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_bluetooth_enumerate_paired" in types


class TestHealthData:
    def test_health_gatt_read_fails(self):
        s = _scanner()
        body = """
        const device = await navigator.bluetooth.requestDevice({filters: [{services: ['heart_rate']}]});
        const server = await device.gatt.connect();
        const service = await server.getPrimaryService('heart_rate');
        const char = await service.getCharacteristic('heart_rate_measurement');
        const value = await char.readValue();
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_bluetooth_health_data_access" in types


class TestAdvertisementScan:
    def test_watch_advertisements_warns(self):
        s = _scanner()
        body = "const device = await navigator.bluetooth.requestDevice({acceptAllDevices: true}); device.watchAdvertisements();"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_bluetooth_advertisement_scan" in types


class TestNotUsed:
    def test_no_bluetooth_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "web_bluetooth_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
