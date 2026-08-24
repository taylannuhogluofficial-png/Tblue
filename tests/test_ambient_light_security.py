"""Tests for AmbientLightSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.ambient_light_security import AmbientLightSecurityScanner


def _scanner():
    s = AmbientLightSecurityScanner.__new__(AmbientLightSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestHighFreqSampling:
    def test_raf_sampling_fails(self):
        s = _scanner()
        body = "const sensor = new AmbientLightSensor(); requestAnimationFrame(() => { console.log(sensor.illuminance) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "ambient_light_high_freq_sampling" in types


class TestDataTransmitted:
    def test_lux_sent_warns(self):
        s = _scanner()
        # _ALS_SEND_RE: illuminance before fetch within 200 non-semicolon chars
        body = "const sensor = new AmbientLightSensor()\nconst lux = sensor.illuminance\nfetch('/stats', {body: lux})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "ambient_light_data_transmitted" in types


class TestAnalyticsShared:
    def test_lux_to_analytics_fails(self):
        s = _scanner()
        body = "const sensor = new AmbientLightSensor()\nanalytics('environment', {illuminance: sensor.illuminance})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "ambient_light_shared_with_analytics" in types


class TestNotUsed:
    def test_no_sensor_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "ambient_light_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
