"""Tests for Social Login Security scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestSocialLoginSecurityScanner:
    def _scanner(self):
        from tblue.scanner.social_login_security import SocialLoginSecurityScanner
        return SocialLoginSecurityScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_social_login_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>no social</html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_missing_state_fails(self):
        s = self._scanner()
        body = (
            '<a href="https://accounts.google.com/o/oauth2/auth'
            '?client_id=123&redirect_uri=https://example.com/callback'
            '&response_type=code">Sign in with Google</a>'
        )
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("state" in r["type"].lower() for r in fails)

    def test_implicit_flow_warns(self):
        s = self._scanner()
        body = (
            '<a href="https://github.com/login/oauth/authorize'
            '?client_id=abc&state=xyz&response_type=token">Login with GitHub</a>'
        )
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("implicit" in r["type"].lower() or "flow" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_oauth_url_no_state(self):
        from tblue.scanner.social_login_security import _check_oauth_url
        url = "https://accounts.google.com/o/oauth2/auth?client_id=x&response_type=code"
        findings = _check_oauth_url(url, URL)
        assert any("state" in f["type"].lower() for f in findings)

    def test_check_oauth_url_with_state_ok(self):
        from tblue.scanner.social_login_security import _check_oauth_url
        url = "https://accounts.google.com/o/oauth2/auth?client_id=x&state=random123&response_type=code"
        findings = _check_oauth_url(url, URL)
        assert not any("state" in f["type"].lower() for f in findings)

    def test_check_oauth_url_implicit_flow(self):
        from tblue.scanner.social_login_security import _check_oauth_url
        url = "https://github.com/login/oauth/authorize?client_id=x&state=y&response_type=token"
        findings = _check_oauth_url(url, URL)
        assert any("implicit" in f["type"].lower() for f in findings)

    def test_count_providers(self):
        from tblue.scanner.social_login_security import _count_social_providers
        body = "Sign in with Google, GitHub, and Facebook"
        assert _count_social_providers(body) >= 3
