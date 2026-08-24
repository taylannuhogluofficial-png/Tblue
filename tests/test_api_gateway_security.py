"""Tests for API Gateway Security scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestAPIGatewaySecurityScanner:
    def _scanner(self):
        from tblue.scanner.api_gateway_security import APIGatewaySecurityScanner
        return APIGatewaySecurityScanner(MagicMock())

    def _resp(self, headers=None, status=200):
        r = MagicMock()
        r.text = "{}"
        r.status_code = status
        r.headers = headers or {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_gateway_headers_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"content-type": "application/json"})):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_kong_header_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"X-Kong-Request-Id": "abc123"})):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("kong" in r["type"].lower() or "gateway" in r["type"].lower() for r in warns)

    def test_aws_apigw_header_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"X-Amzn-RequestId": "req-123"})):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("amzn" in r["type"].lower() or "gateway" in r["type"].lower() for r in warns)

    def test_upstream_header_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"X-Forwarded-Server": "internal-svc-1"})):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("upstream" in r["type"].lower() for r in warns)

    def test_rate_limit_header_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"X-RateLimit-Limit": "100"})):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("rate" in r["type"].lower() for r in warns)

    def test_cors_no_vary_warns(self):
        s = self._scanner()
        headers = {"Access-Control-Allow-Origin": "https://other.com"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("vary" in r["type"].lower() or "cors" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_gateway_vendor_kong(self):
        from tblue.scanner.api_gateway_security import _check_gateway_vendor_headers
        findings = _check_gateway_vendor_headers({"x-kong-request-id": "abc"}, URL)
        assert len(findings) > 0
        assert "kong" in findings[0]["type"].lower()

    def test_check_upstream_disclosure(self):
        from tblue.scanner.api_gateway_security import _check_upstream_disclosure
        result = _check_upstream_disclosure({"x-forwarded-server": "internal"}, URL)
        assert result is not None

    def test_check_upstream_clean(self):
        from tblue.scanner.api_gateway_security import _check_upstream_disclosure
        result = _check_upstream_disclosure({"content-type": "application/json"}, URL)
        assert result is None

    def test_check_rate_limit_present(self):
        from tblue.scanner.api_gateway_security import _check_rate_limit_disclosure
        result = _check_rate_limit_disclosure({"x-ratelimit-limit": "100"}, URL)
        assert result is not None

    def test_check_rate_limit_absent(self):
        from tblue.scanner.api_gateway_security import _check_rate_limit_disclosure
        result = _check_rate_limit_disclosure({"content-type": "text/html"}, URL)
        assert result is None
