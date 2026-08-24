"""Tests for Parameter Pollution scanner."""
from unittest.mock import MagicMock, patch
URL = "https://example.com/?id=1"
URL_CLEAN = "https://example.com/"

class TestParameterPollutionScanner:
    def _scanner(self):
        from tblue.scanner.parameter_pollution import ParameterPollutionScanner
        return ParameterPollutionScanner(MagicMock())
    def _resp(self, body="OK", status=200, headers=None):
        r = MagicMock(); r.text = body; r.status_code = status; r.headers = headers or {}; return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None): results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_no_reflection_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>page</html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_both_values_reflected_warns(self):
        from tblue.scanner.parameter_pollution import _check_duplicate_params_reflected, _PARAM_POLLUTION_PROBE_A, _PARAM_POLLUTION_PROBE_B
        http = MagicMock(); r = MagicMock(); r.status_code = 200
        r.text = f"You searched for {_PARAM_POLLUTION_PROBE_A} and {_PARAM_POLLUTION_PROBE_B}"
        http.get.return_value = r
        findings = _check_duplicate_params_reflected(http, URL)
        assert any("both" in f["type"] for f in findings)

    def test_last_wins_warns(self):
        from tblue.scanner.parameter_pollution import _check_duplicate_params_reflected, _PARAM_POLLUTION_PROBE_A, _PARAM_POLLUTION_PROBE_B
        http = MagicMock(); r = MagicMock(); r.status_code = 200
        r.text = f"Value: {_PARAM_POLLUTION_PROBE_B}"  # only B
        http.get.return_value = r
        findings = _check_duplicate_params_reflected(http, URL)
        assert any("last_wins" in f["type"] for f in findings)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>clean</html>")):
            results = s.scan(URL)
        for r in results: assert r["status"] in ("PASS", "WARN", "FAIL")
