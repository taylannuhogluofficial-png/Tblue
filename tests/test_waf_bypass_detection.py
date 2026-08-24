"""Tests for WAF Bypass Detection scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestWAFBypassDetectionScanner:
    def _scanner(self):
        from tblue.scanner.waf_bypass_detection import WAFBypassDetectionScanner
        return WAFBypassDetectionScanner(MagicMock())

    def _resp(self, headers=None, status=200):
        r = MagicMock()
        r.text = "<html>ok</html>"
        r.status_code = status
        r.headers = headers or {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_waf_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"content-type": "text/html"})):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("waf" in r["type"].lower() or "no" in r["type"].lower() for r in warns)

    def test_waf_present_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"cf-ray": "abc123-LHR"})):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_detect_only_mode_warns(self):
        s = self._scanner()
        headers = {"cf-ray": "abc123", "x-waf-score": "42"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("detect" in r["type"].lower() or "mode" in r["type"].lower() for r in warns)

    def test_origin_ip_disclosed_warns(self):
        s = self._scanner()
        headers = {"cf-ray": "abc123", "x-origin-ip": "192.0.2.1"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("origin" in r["type"].lower() or "ip" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_detect_waf_cloudflare(self):
        from tblue.scanner.waf_bypass_detection import _detect_waf
        assert _detect_waf({"cf-ray": "abc"}) == "Cloudflare"

    def test_detect_waf_sucuri(self):
        from tblue.scanner.waf_bypass_detection import _detect_waf
        assert _detect_waf({"x-sucuri-id": "123"}) == "Sucuri"

    def test_detect_waf_none(self):
        from tblue.scanner.waf_bypass_detection import _detect_waf
        assert _detect_waf({"content-type": "text/html"}) is None

    def test_check_waf_detect_only(self):
        from tblue.scanner.waf_bypass_detection import _check_waf_detect_only
        result = _check_waf_detect_only({"x-waf-score": "50"}, URL)
        assert result is not None

    def test_check_origin_ip_disclosed(self):
        from tblue.scanner.waf_bypass_detection import _check_origin_ip_disclosure
        result = _check_origin_ip_disclosure({"x-origin-ip": "10.0.0.1"}, URL)
        assert result is not None
