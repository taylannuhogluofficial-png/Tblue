"""Tests for GenericSensorSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.generic_sensor_security import GenericSensorSecurityScanner


def _scanner():
    s = GenericSensorSecurityScanner.__new__(GenericSensorSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestDataTransmitted:
    def test_gyro_data_sent_warns(self):
        s = _scanner()
        # _GS_SEND_RE: .x before fetch within 200 non-semicolon chars
        body = "const g = new Gyroscope()\nconst x = g.x\nfetch('/log', {body: x})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "generic_sensor_data_transmitted" in types


class TestAnalyticsTracking:
    def test_orientation_to_analytics_fails(self):
        s = _scanner()
        body = "const g = new Gyroscope()\nanalytics('motion', {x: g.x, y: g.y})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "generic_sensor_analytics_tracking" in types


class TestHighFreq:
    def test_high_freq_config_warns(self):
        s = _scanner()
        body = "const g = new Gyroscope({frequency: 100})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "generic_sensor_high_freq" in types


class TestNotUsed:
    def test_no_sensor_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "generic_sensor_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
