"""Tests for BatteryStatusSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.battery_status_security import BatteryStatusSecurityScanner


def _scanner():
    s = BatteryStatusSecurityScanner.__new__(BatteryStatusSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestFingerprinting:
    def test_battery_level_to_server_warns(self):
        s = _scanner()
        # _BAT_FINGERPRINT_RE: battery.level before fetch within 200 non-semicolon chars
        body = "navigator.getBattery().then(battery => { const level = battery.level\nfetch('/track', {body: level}) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "battery_status_fingerprinting" in types


class TestCrossSiteTracking:
    def test_battery_in_localstorage_fails(self):
        s = _scanner()
        # _BAT_CROSSSITE_RE: battery.level before localStorage within 100 non-semicolon chars
        body = "navigator.getBattery().then(b => { const lvl = b.battery.level\nlocalStorage.setItem('bat', lvl) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "battery_status_cross_site_tracking" in types


class TestHighResTiming:
    def test_charging_time_warns(self):
        s = _scanner()
        body = "navigator.getBattery().then(b => { console.log(b.chargingTime) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "battery_status_high_res_timing" in types


class TestNotUsed:
    def test_no_battery_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "battery_status_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
