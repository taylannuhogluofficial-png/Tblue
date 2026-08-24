"""Tests for Cookie SameSite Deep Analysis scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestCookieSameSiteDeepScanner:
    def _scanner(self):
        from tblue.scanner.cookie_samesite_deep import CookieSameSiteDeepScanner
        return CookieSameSiteDeepScanner(MagicMock())

    def _resp(self, set_cookie=None, status=200):
        r = MagicMock()
        r.text = "<html>ok</html>"
        r.status_code = status
        headers = {}
        if set_cookie:
            headers["Set-Cookie"] = set_cookie
        r.headers = headers
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_cookies_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_samesite_none_without_secure_fails(self):
        s = self._scanner()
        with patch.object(s.http, "get",
                          return_value=self._resp("session=abc; SameSite=None; HttpOnly")):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("none" in r["type"].lower() or "secure" in r["type"].lower() for r in fails)

    def test_missing_samesite_on_session_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get",
                          return_value=self._resp("session=abc; HttpOnly; Secure")):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("missing" in r["type"].lower() or "samesite" in r["type"].lower() for r in warns)

    def test_samesite_lax_on_token_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get",
                          return_value=self._resp("token=xyz; SameSite=Lax; Secure; HttpOnly")):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("lax" in r["type"].lower() for r in warns)

    def test_samesite_strict_ok(self):
        s = self._scanner()
        with patch.object(s.http, "get",
                          return_value=self._resp("session=abc; SameSite=Strict; Secure; HttpOnly")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_host_prefix_without_strict_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get",
                          return_value=self._resp("__Host-token=abc; Secure; Path=/; HttpOnly; SameSite=Lax")):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("host" in r["type"].lower() or "__host" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_parse_set_cookie_samesite_none(self):
        from tblue.scanner.cookie_samesite_deep import _parse_set_cookie
        cookie = _parse_set_cookie("session=abc; SameSite=None; HttpOnly")
        assert cookie["samesite"] == "none"
        assert not cookie["secure"]

    def test_parse_set_cookie_samesite_strict(self):
        from tblue.scanner.cookie_samesite_deep import _parse_set_cookie
        cookie = _parse_set_cookie("auth=xyz; SameSite=Strict; Secure; HttpOnly")
        assert cookie["samesite"] == "strict"
        assert cookie["secure"]

    def test_parse_set_cookie_no_samesite(self):
        from tblue.scanner.cookie_samesite_deep import _parse_set_cookie
        cookie = _parse_set_cookie("session=abc; HttpOnly")
        assert cookie["samesite"] is None

    def test_check_cookie_none_without_secure(self):
        from tblue.scanner.cookie_samesite_deep import _check_cookie
        cookie = {"name": "session", "samesite": "none", "secure": False, "httponly": True, "attrs": set()}
        findings = _check_cookie(cookie, URL)
        assert any("none" in f["type"].lower() for f in findings)

    def test_check_cookie_strict_ok(self):
        from tblue.scanner.cookie_samesite_deep import _check_cookie
        cookie = {"name": "session", "samesite": "strict", "secure": True, "httponly": True, "attrs": set()}
        findings = _check_cookie(cookie, URL)
        assert findings == []
