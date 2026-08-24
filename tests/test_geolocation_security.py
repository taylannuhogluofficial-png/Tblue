"""Tests for GeolocationSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.geolocation_security import GeolocationSecurityScanner


def _scanner():
    s = GeolocationSecurityScanner.__new__(GeolocationSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_geolocation_coords_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.geolocation.getCurrentPosition(pos => {"
        "  const lat = pos.coords.latitude"
        "  sendBeacon('/location', JSON.stringify({lat: lat, lon: pos.coords.longitude}))"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "geolocation_coords_exfil" in types


def test_geolocation_watch_continuous_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.geolocation.watchPosition(pos => {"
        "  fetch('/track', {method: 'POST', body: JSON.stringify(pos)})"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "geolocation_watch_continuous_exfil" in types


def test_geolocation_high_accuracy_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.geolocation.getCurrentPosition(cb, err, {enableHighAccuracy: true})"
        "function cb(pos) { analytics('gps', {coords: pos.coords}) }"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "geolocation_high_accuracy_exfil" in types


def test_geolocation_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No location access here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "geolocation_not_used"
    assert results[0]["status"] == "PASS"


def test_geolocation_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "geolocation_not_used"
