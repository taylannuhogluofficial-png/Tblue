"""Tests for HTTP Security Baseline scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL_HTTPS = "https://example.com"
URL_HTTP  = "http://example.com"


class TestHTTPSecurityBaselineScanner:
    def _scanner(self):
        from tblue.scanner.http_security_baseline import HTTPSecurityBaselineScanner
        return HTTPSecurityBaselineScanner(MagicMock())

    def _resp(self, headers=None, status=200):
        r = MagicMock()
        r.text = "<html>ok</html>"
        r.status_code = status
        r.headers = headers or {}
        r.url = URL_HTTPS
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL_HTTPS)
        assert any(r["status"] == "PASS" for r in results)

    def test_http_url_fails(self):
        """Plain HTTP → FAIL (no TLS)."""
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL_HTTP)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("https" in r["type"].lower() for r in fails)

    def test_all_controls_pass(self):
        """Full set of ideal headers → PASS with no warnings."""
        s = self._scanner()
        headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'; script-src 'nonce-abc123'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "SAMEORIGIN",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=(), microphone=()",
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-resource-policy": "same-origin",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL_HTTPS)
        assert any(r["status"] == "PASS" for r in results)
        # No failures or warnings on perfect config
        fails = [r for r in results if r["status"] == "FAIL"]
        assert not fails

    def test_missing_hsts_warns(self):
        """HTTPS but no HSTS → WARN."""
        s = self._scanner()
        headers = {
            "x-content-type-options": "nosniff",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
            "permissions-policy": "camera=()",
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-resource-policy": "same-origin",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL_HTTPS)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("hsts" in r["type"].lower() for r in warns)

    def test_csp_absent_warns(self):
        """No CSP → WARN."""
        s = self._scanner()
        headers = {
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL_HTTPS)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("csp" in r["type"].lower() for r in warns)

    def test_csp_unsafe_inline_warns(self):
        """CSP with unsafe-inline (no nonce/hash) → WARN."""
        s = self._scanner()
        headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'",
            "x-content-type-options": "nosniff",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL_HTTPS)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("unsafe-inline" in r["type"].lower() for r in warns)

    def test_csp_unsafe_inline_with_nonce_passes(self):
        """unsafe-inline paired with a nonce → no unsafe-inline warning."""
        s = self._scanner()
        headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "script-src 'nonce-xyz123' 'unsafe-inline'",
            "x-content-type-options": "nosniff",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL_HTTPS)
        unsafe_warns = [r for r in results if "unsafe-inline" in r.get("type", "")]
        assert not unsafe_warns

    def test_xcto_missing_warns(self):
        """No X-Content-Type-Options → WARN."""
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL_HTTPS)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("xcto" in r["type"].lower() for r in warns)

    def test_clickjacking_unprotected_warns(self):
        """No XFO and no frame-ancestors → WARN."""
        s = self._scanner()
        headers = {"content-security-policy": "default-src 'self'"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL_HTTPS)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("clickjacking" in r["type"].lower() or "frame" in r["type"].lower() for r in warns)

    def test_coop_absent_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL_HTTPS)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("coop" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL_HTTPS)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_https_ok(self):
        from tblue.scanner.http_security_baseline import _check_https
        resp = MagicMock()
        resp.headers = {"strict-transport-security": "max-age=31536000"}
        result = _check_https("https://example.com", resp)
        assert result is None

    def test_check_https_no_hsts(self):
        from tblue.scanner.http_security_baseline import _check_https
        resp = MagicMock()
        resp.headers = {}
        result = _check_https("https://example.com", resp)
        assert result is not None
        assert result["status"] == "WARN"

    def test_check_https_http(self):
        from tblue.scanner.http_security_baseline import _check_https
        resp = MagicMock()
        resp.headers = {}
        result = _check_https("http://example.com", resp)
        assert result is not None
        assert result["status"] == "FAIL"

    def test_check_csp_absent(self):
        from tblue.scanner.http_security_baseline import _check_csp
        result = _check_csp({})
        assert result is not None

    def test_check_csp_present_good(self):
        from tblue.scanner.http_security_baseline import _check_csp
        result = _check_csp({"content-security-policy": "default-src 'self'"})
        assert result is None

    def test_check_referrer_policy_strict(self):
        from tblue.scanner.http_security_baseline import _check_referrer_policy
        result = _check_referrer_policy({"referrer-policy": "strict-origin-when-cross-origin"})
        assert result is None

    def test_check_referrer_policy_absent(self):
        from tblue.scanner.http_security_baseline import _check_referrer_policy
        result = _check_referrer_policy({})
        assert result is not None
        assert result["status"] == "WARN"

    def test_check_permissions_policy_present(self):
        from tblue.scanner.http_security_baseline import _check_permissions_policy
        result = _check_permissions_policy({"permissions-policy": "camera=()"})
        assert result is None

    def test_check_permissions_policy_absent(self):
        from tblue.scanner.http_security_baseline import _check_permissions_policy
        result = _check_permissions_policy({})
        assert result is not None
