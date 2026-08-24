"""Tests for Clickjacking Deep scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestClickjackingDeepScanner:
    def _scanner(self):
        from tblue.scanner.clickjacking_deep import ClickjackingDeepScanner
        return ClickjackingDeepScanner(MagicMock())

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        r.url = URL
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_protection_fails(self):
        """No XFO and no frame-ancestors → FAIL."""
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("no-protection" in r["type"].lower() or "clickjacking" in r["type"].lower() for r in fails)

    def test_csp_frame_ancestors_none_passes(self):
        """CSP frame-ancestors 'none' → PASS."""
        s = self._scanner()
        headers = {"content-security-policy": "default-src 'self'; frame-ancestors 'none'"}
        with patch.object(s.http, "get", return_value=self._resp(headers=headers)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_csp_frame_ancestors_self_warns(self):
        """frame-ancestors 'self' → WARN (should use 'none' for sensitive pages)."""
        s = self._scanner()
        headers = {"content-security-policy": "frame-ancestors 'self'"}
        with patch.object(s.http, "get", return_value=self._resp(headers=headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("self" in r["type"].lower() or "frame-ancestors" in r["type"].lower() for r in warns)

    def test_xfo_deny_without_csp_warns(self):
        """XFO: DENY without CSP frame-ancestors → WARN."""
        s = self._scanner()
        headers = {"x-frame-options": "DENY"}
        with patch.object(s.http, "get", return_value=self._resp(headers=headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("xfo-only" in r["type"].lower() or "no-csp" in r["type"].lower() for r in warns)

    def test_xfo_allow_from_deprecated_warns(self):
        """XFO: ALLOW-FROM is deprecated → WARN."""
        s = self._scanner()
        headers = {"x-frame-options": "ALLOW-FROM https://trusted.com"}
        with patch.object(s.http, "get", return_value=self._resp(headers=headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("allow-from" in r["type"].lower() or "deprecated" in r["type"].lower() for r in warns)

    def test_frame_busting_js_without_csp_warns(self):
        """JS frame-busting without CSP → WARN."""
        s = self._scanner()
        body = "<script>if (top !== self) top.location = self.location;</script>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("frame-busting" in r["type"].lower() or "js" in r["type"].lower() for r in warns)

    def test_frame_busting_with_csp_no_extra_warn(self):
        """JS frame-busting with CSP frame-ancestors → no extra frame-busting warning."""
        s = self._scanner()
        body = "<script>if (top !== self) top.location = self.location;</script>"
        headers = {"content-security-policy": "frame-ancestors 'none'"}
        with patch.object(s.http, "get", return_value=self._resp(body, headers=headers)):
            results = s.scan(URL)
        fb_warns = [r for r in results if "frame-busting" in r.get("type", "").lower()]
        assert not fb_warns

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_protection_no_xfo_no_csp(self):
        from tblue.scanner.clickjacking_deep import _check_protection
        findings = _check_protection({}, URL)
        assert any("no-protection" in f["type"].lower() for f in findings)

    def test_check_protection_frame_ancestors_none(self):
        from tblue.scanner.clickjacking_deep import _check_protection
        headers = {"content-security-policy": "frame-ancestors 'none'"}
        findings = _check_protection(headers, URL)
        no_prot = [f for f in findings if "no-protection" in f["type"].lower()]
        assert not no_prot

    def test_check_protection_allow_from(self):
        from tblue.scanner.clickjacking_deep import _check_protection
        headers = {"x-frame-options": "ALLOW-FROM https://trusted.com"}
        findings = _check_protection(headers, URL)
        assert any("allow-from" in f["type"].lower() for f in findings)

    def test_check_frame_busting_detected(self):
        from tblue.scanner.clickjacking_deep import _check_frame_busting_without_csp
        body = "if (window.top !== window.self) window.top.location = window.self.location;"
        result = _check_frame_busting_without_csp(body, {}, URL)
        assert result is not None

    def test_check_frame_busting_with_csp_no_finding(self):
        from tblue.scanner.clickjacking_deep import _check_frame_busting_without_csp
        body = "if (top !== self) top.location = self.location;"
        headers = {"content-security-policy": "frame-ancestors 'self'"}
        result = _check_frame_busting_without_csp(body, headers, URL)
        assert result is None

    def test_get_frame_ancestors(self):
        from tblue.scanner.clickjacking_deep import _get_frame_ancestors
        headers = {"content-security-policy": "default-src 'self'; frame-ancestors 'none'; script-src 'nonce-abc'"}
        result = _get_frame_ancestors(headers)
        assert result == "'none'"

    def test_get_frame_ancestors_absent(self):
        from tblue.scanner.clickjacking_deep import _get_frame_ancestors
        result = _get_frame_ancestors({"content-security-policy": "default-src 'self'"})
        assert result is None
