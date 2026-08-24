"""Tests for CDN Misconfiguration scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestCDNMisconfigurationScanner:
    def _scanner(self):
        from tblue.scanner.cdn_misconfiguration import CDNMisconfigurationScanner
        return CDNMisconfigurationScanner(MagicMock())

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

    def test_no_cdn_headers_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"content-type": "text/html"})):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_cf_ray_header_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"CF-Ray": "abc123-LHR"})):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("cdn" in r["type"].lower() or "header" in r["type"].lower() for r in warns)

    def test_excessive_swr_warns(self):
        s = self._scanner()
        headers = {"cache-control": "public, max-age=60, stale-while-revalidate=172800"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("stale" in r["type"].lower() or "revalidate" in r["type"].lower() for r in warns)

    def test_age_anomaly_warns(self):
        s = self._scanner()
        headers = {"age": "3600", "cache-control": "public, max-age=60"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("age" in r["type"].lower() for r in warns)

    def test_cors_wildcard_with_cdn_warns(self):
        s = self._scanner()
        headers = {
            "access-control-allow-origin": "*",
            "cf-ray": "123abc",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("cors" in r["type"].lower() or "wildcard" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_detect_cdn_cloudflare(self):
        from tblue.scanner.cdn_misconfiguration import _detect_cdn
        assert _detect_cdn({"cf-ray": "abc"}) == "Cloudflare"

    def test_detect_cdn_none(self):
        from tblue.scanner.cdn_misconfiguration import _detect_cdn
        assert _detect_cdn({"content-type": "text/html"}) is None

    def test_check_swr_normal(self):
        from tblue.scanner.cdn_misconfiguration import _check_stale_while_revalidate
        headers = {"cache-control": "public, max-age=3600, stale-while-revalidate=60"}
        assert _check_stale_while_revalidate(headers, URL) is None

    def test_check_age_normal(self):
        from tblue.scanner.cdn_misconfiguration import _check_age_anomaly
        headers = {"age": "30", "cache-control": "public, max-age=3600"}
        assert _check_age_anomaly(headers, URL) is None
