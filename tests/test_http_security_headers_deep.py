"""Tests for HTTPSecurityHeadersDeepScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.http_security_headers_deep import HTTPSecurityHeadersDeepScanner

URL = "https://example.com"


class TestHTTPSecurityHeadersDeep:
    def _scanner(self):
        return HTTPSecurityHeadersDeepScanner(MagicMock())

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_missing_hsts_on_https_fails(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(headers={})):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL" and "hsts" in r["type"]]
        assert len(fails) > 0

    def test_hsts_short_max_age_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(headers={
            "strict-transport-security": "max-age=3600; includeSubDomains",
            "x-content-type-options": "nosniff",
        })):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "max_age" in r["type"]]
        assert len(warns) > 0

    def test_hsts_missing_includesubdomains_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(headers={
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
        })):
            results = s.scan(URL)
        warns = [r for r in results if "includesubdomains" in r["type"] or "subdomain" in r["type"]]
        assert len(warns) > 0

    def test_missing_xcto_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(headers={
            "strict-transport-security": "max-age=31536000; includeSubDomains",
        })):
            results = s.scan(URL)
        warns = [r for r in results if "xcto" in r["type"] or "content_type" in r["type"].lower()]
        assert len(warns) > 0

    def test_referrer_policy_permissive_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(headers={
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "x-content-type-options": "nosniff",
            "referrer-policy": "unsafe-url",
        })):
            results = s.scan(URL)
        warns = [r for r in results if "referrer" in r["type"]]
        assert len(warns) > 0

    def test_good_headers_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(headers={
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=(), microphone=()",
        })):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(headers={})):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL", "INFO")
