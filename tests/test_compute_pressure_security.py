"""Tests for ComputePressureSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.compute_pressure_security import ComputePressureSecurityScanner


def _scanner():
    s = ComputePressureSecurityScanner.__new__(ComputePressureSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestStateExfil:
    def test_pressure_state_exfiltrated_fails(self):
        s = _scanner()
        body = "const obs = new PressureObserver(records => { const state = records[0].state\nsendBeacon('/pressure', state) })\nobs.observe('cpu')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "compute_pressure_state_exfiltrated" in types


class TestActivityDetection:
    def test_activity_inference_warns(self):
        s = _scanner()
        body = "const obs = new PressureObserver(records => { if (records[0].state === 'serious') { initiatePayment() } })\nobs.observe('cpu')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "compute_pressure_activity_detection" in types


class TestContinuousMonitor:
    def test_continuous_monitoring_warns(self):
        s = _scanner()
        body = "const monitor = new PressureObserver(cb)\nsetInterval(() => monitor.observe('cpu'), 1000)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "compute_pressure_continuous_monitoring" in types


class TestNotUsed:
    def test_no_pressure_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "compute_pressure_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
