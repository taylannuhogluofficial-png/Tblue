"""Tests for Cookie Prefix Security scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestCookiePrefixSecurityScanner:
    def _scanner(self):
        from tblue.scanner.cookie_prefix_security import CookiePrefixSecurityScanner
        return CookiePrefixSecurityScanner(MagicMock())

    def _resp(self, status=200, cookies=None):
        r = MagicMock()
        r.status_code = status
        r.text = "<html></html>"
        r.url = URL

        if cookies:
            # Simulate headers.get and headers.get_all
            first = cookies[0] if cookies else ""
            r.headers.get = lambda k, d="": first if k.lower() == "set-cookie" else d
            r.headers.get_all = lambda k: cookies if k.lower() == "set-cookie" else []
        else:
            r.headers.get = lambda k, d="": d
            r.headers.get_all = lambda k: []
        return r

    def test_no_cookies_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_host_prefix_no_secure_fails(self):
        """__Host- cookie without Secure attribute → FAIL."""
        s = self._scanner()
        cookie = "__Host-session=abc; Path=/; HttpOnly"
        with patch.object(s.http, "get", return_value=self._resp(cookies=[cookie])):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("__Host-" in r["type"] or "Secure" in r["description"] for r in fails)

    def test_host_prefix_with_domain_fails(self):
        """__Host- cookie with Domain attribute → FAIL."""
        s = self._scanner()
        cookie = "__Host-session=abc; Secure; Path=/; Domain=example.com; HttpOnly"
        with patch.object(s.http, "get", return_value=self._resp(cookies=[cookie])):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails, "Domain on __Host- cookie should fail"

    def test_host_prefix_wrong_path_fails(self):
        """__Host- cookie with Path=/admin instead of / → FAIL."""
        s = self._scanner()
        cookie = "__Host-session=abc; Secure; Path=/admin; HttpOnly"
        with patch.object(s.http, "get", return_value=self._resp(cookies=[cookie])):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails, "Path=/admin on __Host- should fail"

    def test_secure_prefix_no_secure_fails(self):
        """__Secure- cookie without Secure → FAIL."""
        s = self._scanner()
        cookie = "__Secure-token=xyz; HttpOnly"
        with patch.object(s.http, "get", return_value=self._resp(cookies=[cookie])):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails

    def test_valid_host_prefix_passes(self):
        """__Host- with Secure + Path=/ + no Domain → compliant."""
        s = self._scanner()
        # Name doesn't match session pattern so no hardening warnings
        cookie = "__Host-csrf=token; Secure; Path=/; HttpOnly; SameSite=Strict"
        with patch.object(s.http, "get", return_value=self._resp(cookies=[cookie])):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        # No prefix compliance failures
        prefix_fails = [r for r in fails if "prefix" in r.get("type", "").lower() or "__Host-" in r.get("description", "")]
        assert not prefix_fails

    def test_samesite_none_without_secure_fails(self):
        """SameSite=None without Secure → FAIL."""
        s = self._scanner()
        cookie = "session=abc; SameSite=None; HttpOnly"
        with patch.object(s.http, "get", return_value=self._resp(cookies=[cookie])):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("SameSite" in r.get("type", "") or "samesite" in r.get("type", "").lower() for r in fails)

    def test_session_cookie_no_httponly_warns(self):
        """session cookie without HttpOnly → WARN."""
        s = self._scanner()
        cookie = "session=abc; Secure; SameSite=Strict"
        with patch.object(s.http, "get", return_value=self._resp(cookies=[cookie])):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("HttpOnly" in r.get("type", "") or "httponly" in r.get("type", "").lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_parse_cookie_basic(self):
        from tblue.scanner.cookie_prefix_security import _parse_cookie
        c = _parse_cookie("session=abc; Secure; HttpOnly; Path=/; SameSite=Strict")
        assert c["name"] == "session"
        assert c["secure"]
        assert c["httponly"]
        assert c["samesite"] == "strict"
        assert c["path"] == "/"

    def test_parse_cookie_with_domain(self):
        from tblue.scanner.cookie_prefix_security import _parse_cookie
        c = _parse_cookie("__Host-x=1; Secure; Path=/; Domain=example.com")
        assert c["domain"] == "example.com"

    def test_check_prefix_host_violations(self):
        from tblue.scanner.cookie_prefix_security import _check_prefix_compliance, _parse_cookie
        c = _parse_cookie("__Host-bad=x; Path=/admin")
        findings = _check_prefix_compliance(c)
        types = [f["type"] for f in findings]
        assert "cookie-prefix-host-no-secure" in types
        assert "cookie-prefix-host-wrong-path" in types

    def test_check_prefix_secure_violation(self):
        from tblue.scanner.cookie_prefix_security import _check_prefix_compliance, _parse_cookie
        c = _parse_cookie("__Secure-token=abc; HttpOnly")
        findings = _check_prefix_compliance(c)
        assert any(f["type"] == "cookie-prefix-secure-no-secure" for f in findings)
