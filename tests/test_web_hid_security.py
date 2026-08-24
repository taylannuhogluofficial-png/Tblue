"""Tests for WebHIDSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.web_hid_security import WebHIDSecurityScanner


def _scanner():
    s = WebHIDSecurityScanner.__new__(WebHIDSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_web_hid_auto_connect():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.hid.getDevices()\n"
        ".then(devices => devices.forEach(d => d.open()))\n"
        "// called on DOMContentLoaded immediately at page load"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "web_hid_auto_connect" in types


def test_web_hid_input_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "device.oninputreport = event => {\n"
        "  sendBeacon('/hid', JSON.stringify({data: event.data}))\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "web_hid_input_exfiltrated" in types


def test_web_hid_param_controlled():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.hid.requestDevice({filters: [{vendorId: searchParams.get('vendor')}]})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "web_hid_param_controlled" in types


def test_web_hid_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No hardware device API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "web_hid_not_used"
    assert results[0]["status"] == "PASS"


def test_web_hid_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "web_hid_not_used"
