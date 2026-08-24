"""Tests for CORS Preflight Deep scanner."""
from unittest.mock import MagicMock, patch
URL = "https://example.com"

class TestCORSPreflightDeepScanner:
    def _scanner(self):
        from tblue.scanner.cors_preflight_deep import CORSPreflightDeepScanner
        return CORSPreflightDeepScanner(MagicMock())
    def _resp(self, body="OK", status=200, headers=None):
        r = MagicMock(); r.text = body; r.status_code = status; r.headers = headers or {}; return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None): results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_cors_passes(self):
        from tblue.scanner.cors_preflight_deep import _check_cors_preflight_response
        findings = _check_cors_preflight_response({"access-control-allow-origin": "https://example.com"}, URL)
        assert not any(f["status"] == "FAIL" for f in findings)

    def test_reflected_with_credentials_fails(self):
        from tblue.scanner.cors_preflight_deep import _check_cors_preflight_response, _PROBE_ORIGIN
        h = {"access-control-allow-origin": _PROBE_ORIGIN, "access-control-allow-credentials": "true"}
        findings = _check_cors_preflight_response(h, URL)
        assert any("reflected_with_credentials" in f["type"] for f in findings)

    def test_missing_vary_origin_warns(self):
        from tblue.scanner.cors_preflight_deep import _check_cors_preflight_response, _PROBE_ORIGIN
        h = {"access-control-allow-origin": _PROBE_ORIGIN}
        findings = _check_cors_preflight_response(h, URL)
        assert any("vary" in f["type"] for f in findings)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results: assert r["status"] in ("PASS", "WARN", "FAIL")
