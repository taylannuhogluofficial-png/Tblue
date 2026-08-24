"""Tests for BeaconAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.beacon_api_security import BeaconAPISecurityScanner


def _scanner():
    s = BeaconAPISecurityScanner.__new__(BeaconAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestCredentials:
    def test_beacon_sends_credentials_fails(self):
        s = _scanner()
        body = "navigator.sendBeacon('/track', JSON.stringify({token: localStorage.getItem('auth_token')}))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "beacon_sends_credentials" in types


class TestExternalURL:
    def test_beacon_to_external_url_warns(self):
        s = _scanner()
        body = "sendBeacon('https://analytics.tracker.io/collect', payload)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "beacon_to_external_url" in types


class TestURLFromParam:
    def test_beacon_url_from_param_fails(self):
        s = _scanner()
        body = "navigator.sendBeacon(searchParams.get('endpoint'), data)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "beacon_url_from_url_param" in types


class TestNotUsed:
    def test_no_beacon_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "beacon_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
