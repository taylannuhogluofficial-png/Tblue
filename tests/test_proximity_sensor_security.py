"""Tests for ProximitySensorSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.proximity_sensor_security import ProximitySensorSecurityScanner


def _scanner():
    s = ProximitySensorSecurityScanner.__new__(ProximitySensorSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_proximity_sensor_data_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const sensor = new ProximitySensor()\n"
        "sensor.onreading = () => {\n"
        "  const near = sensor.near\n"
        "  const distance = sensor.distance\n"
        "  fetch('/log', {body: JSON.stringify({near, distance})})\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "proximity_sensor_data_exfiltrated" in types


def test_proximity_sensor_activity_inference():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const sensor = new ProximitySensor()\n"
        "sensor.onreading = () => {\n"
        "  if (sensor.near) {\n"
        "    document.getElementById('login').submit()\n"
        "  }\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "proximity_sensor_activity_inference" in types


def test_proximity_sensor_continuous_monitoring():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const sensor = new ProximitySensor()\n"
        "setInterval(() => { if(sensor.near) sendBeacon('/ping') }, 500)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "proximity_sensor_continuous_monitoring" in types


def test_proximity_sensor_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No sensor here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "proximity_sensor_not_used"
    assert results[0]["status"] == "PASS"


def test_proximity_sensor_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "proximity_sensor_not_used"
