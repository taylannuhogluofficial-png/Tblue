"""Tests for Rate Limiting Detection scanner."""
from unittest.mock import MagicMock, patch
URL = "https://example.com"

class TestRateLimitingDetectionScanner:
    def _scanner(self):
        from tblue.scanner.rate_limiting_detection import RateLimitingDetectionScanner
        return RateLimitingDetectionScanner(MagicMock())
    def _resp(self, body="OK", status=200, headers=None):
        r = MagicMock(); r.text = body; r.status_code = status; r.headers = headers or {}; return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None): results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_rate_limit_headers_present_passes(self):
        from tblue.scanner.rate_limiting_detection import _check_rate_limit_headers_present
        findings = _check_rate_limit_headers_present({"x-ratelimit-limit": "100", "x-ratelimit-remaining": "99"}, URL)
        assert findings == []

    def test_no_rate_limit_headers_warns(self):
        from tblue.scanner.rate_limiting_detection import _check_rate_limit_headers_present
        findings = _check_rate_limit_headers_present({}, URL)
        assert any("no_headers" in f["type"] for f in findings)

    def test_auth_endpoint_no_429_fails(self):
        from tblue.scanner.rate_limiting_detection import _check_auth_endpoint_rate_limited
        http = MagicMock()
        r = MagicMock(); r.status_code = 200; r.text = "Login"
        http.get.return_value = r
        findings = _check_auth_endpoint_rate_limited(http, "https://example.com")
        assert any("unrestricted" in f["type"] for f in findings)

    def test_auth_endpoint_429_passes(self):
        from tblue.scanner.rate_limiting_detection import _check_auth_endpoint_rate_limited
        http = MagicMock()
        r = MagicMock(); r.status_code = 429; r.text = "Too Many Requests"
        http.get.return_value = r
        findings = _check_auth_endpoint_rate_limited(http, "https://example.com")
        assert findings == []

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(headers={"x-ratelimit-limit": "100"})):
            results = s.scan(URL)
        for r in results: assert r["status"] in ("PASS", "WARN", "FAIL")
