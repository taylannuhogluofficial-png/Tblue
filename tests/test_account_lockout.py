"""Tests for Account Lockout / Brute Force Protection scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestAccountLockoutScanner:
    def _scanner(self):
        from tblue.scanner.account_lockout import AccountLockoutScanner
        return AccountLockoutScanner(MagicMock())

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

    def test_no_login_endpoint_passes(self):
        """No login page found at any common path → PASS."""
        s = self._scanner()
        not_found = self._resp("", 404)
        root = self._resp("<html>hello</html>", 200)

        def get_side(url, **kwargs):
            return root if url == URL else not_found

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_login_with_rate_limit_header_passes(self):
        """Login page returns X-RateLimit-Limit → protection detected → PASS."""
        s = self._scanner()
        login_resp = self._resp("<form>login</form>", 200,
                                headers={"x-ratelimit-limit": "5"})
        root = self._resp("<html>home</html>", 200)

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "/login" in url:
                return login_resp
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_login_with_captcha_passes(self):
        """Login page contains reCAPTCHA → protection → PASS."""
        s = self._scanner()
        login_body = "<form>login <script src='https://www.google.com/recaptcha/api.js'></script></form>"
        login_resp = self._resp(login_body, 200)
        root = self._resp("<html>home</html>", 200)

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "/login" in url:
                return login_resp
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_login_with_mfa_passes(self):
        """Login page contains 2FA reference → MFA protection → PASS."""
        s = self._scanner()
        login_body = "<form>login <p>We support two-factor authentication</p></form>"
        login_resp = self._resp(login_body, 200)
        root = self._resp("<html>home</html>", 200)

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "/login" in url:
                return login_resp
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_login_no_protection_warns(self):
        """Login page with no protection signals → WARN."""
        s = self._scanner()
        login_body = "<form><input name='user'><input name='pass'><button>Login</button></form>"
        login_resp = self._resp(login_body, 200)
        root = self._resp("<html>home</html>", 200)

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "/login" in url:
                return login_resp
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert warns

    def test_login_lockout_text_passes(self):
        """Login page with 'too many attempts' text → lockout messaging → PASS."""
        s = self._scanner()
        login_body = "<form>login <p>Too many attempts. Please retry after 30 seconds.</p></form>"
        login_resp = self._resp(login_body, 200)
        root = self._resp("<html>home</html>", 200)

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "/login" in url:
                return login_resp
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_cloudflare_waf_passes(self):
        """Login page with cf-ray header → WAF protection → PASS."""
        s = self._scanner()
        login_resp = self._resp("<form>login</form>", 200,
                                headers={"cf-ray": "7abc123-SIN"})
        root = self._resp("<html>home</html>", 200)

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "/login" in url:
                return login_resp
            return self._resp("", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("", 404)):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_rate_limit_headers_present(self):
        from tblue.scanner.account_lockout import _check_rate_limit_headers
        headers = {"x-ratelimit-limit": "10", "content-type": "text/html"}
        result = _check_rate_limit_headers(headers)
        assert result is not None

    def test_check_rate_limit_headers_absent(self):
        from tblue.scanner.account_lockout import _check_rate_limit_headers
        headers = {"content-type": "text/html"}
        result = _check_rate_limit_headers(headers)
        assert result is None

    def test_check_captcha_recaptcha(self):
        from tblue.scanner.account_lockout import _check_captcha
        body = '<script src="https://www.google.com/recaptcha/api.js"></script>'
        result = _check_captcha(body)
        assert result is not None
        assert "reCAPTCHA" in result

    def test_check_captcha_hcaptcha(self):
        from tblue.scanner.account_lockout import _check_captcha
        body = '<script src="https://js.hcaptcha.com/1/api.js"></script>'
        result = _check_captcha(body)
        assert result is not None

    def test_check_captcha_absent(self):
        from tblue.scanner.account_lockout import _check_captcha
        body = "<form><input name='user'><input name='pass'></form>"
        result = _check_captcha(body)
        assert result is None

    def test_check_mfa_totp(self):
        from tblue.scanner.account_lockout import _check_mfa
        body = "<p>Enter your TOTP code</p>"
        result = _check_mfa(body)
        assert result is not None

    def test_check_mfa_webauthn(self):
        from tblue.scanner.account_lockout import _check_mfa
        body = "<p>Sign in with your passkey or WebAuthn device</p>"
        result = _check_mfa(body)
        assert result is not None

    def test_check_mfa_absent(self):
        from tblue.scanner.account_lockout import _check_mfa
        body = "<form><input name='password'></form>"
        result = _check_mfa(body)
        assert result is None

    def test_check_waf_cloudflare(self):
        from tblue.scanner.account_lockout import _check_waf_headers
        headers = {"cf-ray": "7abc-LHR", "content-type": "text/html"}
        result = _check_waf_headers(headers)
        assert result == "Cloudflare"

    def test_check_waf_absent(self):
        from tblue.scanner.account_lockout import _check_waf_headers
        headers = {"content-type": "text/html"}
        result = _check_waf_headers(headers)
        assert result is None
