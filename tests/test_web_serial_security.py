"""Tests for WebSerialSecurityScanner."""
import pytest
from unittest.mock import MagicMock
from tblue.scanner.web_serial_security import WebSerialSecurityScanner


def _scanner():
    s = WebSerialSecurityScanner.__new__(WebSerialSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestPortEnumeration:
    def test_get_ports_warns(self):
        s = _scanner()
        body = "const ports = await navigator.serial.getPorts();"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_serial_enumerate_ports" in types


class TestDataFromURL:
    def test_data_from_url_param_fails(self):
        s = _scanner()
        # _SERIAL_DATA_FROM_URL_RE matches 'writer.write([^)]*searchParams)' or 'TextEncoder([^)]*searchParams)'
        # Use direct writer.write(searchParams...) without nested call to keep 'searchParams' before first ')'
        body = """
        const port = await navigator.serial.requestPort();
        await port.open({ baudRate: 9600 });
        const writer = port.writable.getWriter();
        writer.write(searchParams.get('cmd'));
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_serial_data_from_url" in types
        assert any(r["status"] == "FAIL" for r in results)


class TestPortInfoTransmitted:
    def test_port_info_sent_warns(self):
        s = _scanner()
        body = """
        const ports = await navigator.serial.getPorts();
        const info = ports[0].getInfo();
        fetch('/log', {body: JSON.stringify({vid: info.usbVendorId})});
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_serial_port_info_transmitted" in types


class TestNoFilters:
    def test_no_filters_warns(self):
        s = _scanner()
        body = "const port = await navigator.serial.requestPort();"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_serial_no_filters" in types

    def test_with_filters_passes(self):
        s = _scanner()
        body = "const port = await navigator.serial.requestPort({ filters: [{usbVendorId: 0x1234}] });"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_serial_no_filters" not in types


class TestNotUsed:
    def test_no_serial_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "web_serial_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
