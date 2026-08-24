"""Tests for ActuatorEndpointExposureScanner."""
from unittest.mock import MagicMock
from tblue.scanner.actuator_endpoint_exposure import ActuatorEndpointExposureScanner


def _scanner():
    s = ActuatorEndpointExposureScanner.__new__(ActuatorEndpointExposureScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_spring_actuator_exposed():
    s = _scanner()
    s.http.get.return_value = _resp(
        '{"_links": {"actuator": {"href": "http://app/actuator"}, '
        '"health": {"href": "http://app/actuator/health"}}}'
    )
    results = s.scan("http://example.com/actuator")
    types = [r["type"] for r in results]
    assert "actuator_spring_actuator_exposed" in types


def test_actuator_env_disclosure():
    s = _scanner()
    s.http.get.return_value = _resp(
        '{"activeProfiles": [], "propertySources": [{'
        '"name": "systemEnvironment", "properties": {"DB_PASSWORD": {"value": "secret"}}}]}'
    )
    results = s.scan("http://example.com/actuator/env")
    types = [r["type"] for r in results]
    assert "actuator_env_disclosure" in types


def test_prometheus_exposed():
    s = _scanner()
    s.http.get.return_value = _resp(
        "# HELP http_requests_total Total HTTP requests\n"
        "# TYPE http_requests_total counter\n"
        'http_requests_total{method="GET",status="200"} 1234'
    )
    results = s.scan("http://example.com/metrics")
    types = [r["type"] for r in results]
    assert "actuator_prometheus_exposed" in types


def test_health_detail_exposed():
    s = _scanner()
    s.http.get.return_value = _resp(
        '{"status": "UP", "components": {"db": {"status": "UP"}, "redis": {"status": "UP"}}}'
    )
    results = s.scan("http://example.com/actuator/health")
    types = [r["type"] for r in results]
    assert "actuator_health_detail_exposed" in types


def test_actuator_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Regular page</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "actuator_endpoint_not_used"
    assert results[0]["status"] == "PASS"
