"""Tests for Sensitive Endpoint Exposure scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestSensitiveEndpointExposureScanner:
    def _scanner(self):
        from tblue.scanner.sensitive_endpoint_exposure import SensitiveEndpointExposureScanner
        return SensitiveEndpointExposureScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_site_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>OK</html>", 404)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_prometheus_metrics_fails(self):
        s = self._scanner()

        def get_side(url, **kwargs):
            if "/metrics" in url:
                return self._resp("# HELP process_cpu_seconds_total\n# TYPE counter", 200)
            return self._resp("<html>OK</html>", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("metrics" in r["type"] or "prometheus" in r["type"] for r in fails)

    def test_spring_actuator_fails(self):
        s = self._scanner()

        def get_side(url, **kwargs):
            if "/actuator" in url and "/env" not in url and "/heap" not in url:
                return self._resp('{"_links": {"health": {}}}', 200)
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("actuator" in r["type"] for r in fails)

    def test_pprof_debug_fails(self):
        s = self._scanner()

        def get_side(url, **kwargs):
            if "/debug/pprof/" in url:
                return self._resp("Types of profiles available:\ngoroutine", 200)
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("pprof" in r["type"] or "debug" in r["type"] for r in fails)

    def test_swagger_ui_warns(self):
        s = self._scanner()

        def get_side(url, **kwargs):
            if "/swagger-ui.html" in url:
                return self._resp("<html>Swagger UI</html>", 200)
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        found = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("swagger" in r["type"] for r in found)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
