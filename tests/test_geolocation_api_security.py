"""Tests for GeolocationAPISecurityScanner."""
import pytest
from unittest.mock import MagicMock
from tblue.scanner.geolocation_api_security import GeolocationAPISecurityScanner


def _scanner():
    s = GeolocationAPISecurityScanner.__new__(GeolocationAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestContinuousNoStop:
    def test_watch_without_clear_warns(self):
        s = _scanner()
        body = "navigator.geolocation.watchPosition(success, error, {timeout: 5000});"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "geo_api_continuous_no_clear" in types

    def test_watch_with_clear_passes(self):
        s = _scanner()
        body = """
        const wid = navigator.geolocation.watchPosition(success);
        button.onclick = () => navigator.geolocation.clearWatch(wid);
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "geo_api_continuous_no_clear" not in types


class TestHighAccuracy:
    def test_high_accuracy_warns(self):
        s = _scanner()
        body = "navigator.geolocation.getCurrentPosition(success, error, {enableHighAccuracy: true});"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "geo_api_high_accuracy" in types


class TestThirdPartyAnalytics:
    def test_location_shared_with_analytics_fails(self):
        s = _scanner()
        body = """
        navigator.geolocation.getCurrentPosition(pos => {
            gtag('event', 'location', {latitude: pos.coords.latitude, longitude: pos.coords.longitude});
        });
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "geo_api_shared_with_analytics" in types
        assert any(r["status"] == "FAIL" for r in results)


class TestNotUsed:
    def test_no_geolocation_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "geo_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
