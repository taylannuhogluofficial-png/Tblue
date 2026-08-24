"""Tests for MFA Detection scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestMFADetectionScanner:
    def _scanner(self):
        from tblue.scanner.mfa_detection import MFADetectionScanner
        return MFADetectionScanner(MagicMock())

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

    def test_no_login_page_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(status=404)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_login_form_without_mfa_warns(self):
        s = self._scanner()
        login_body = '<form><input type="text" name="username"><input type="password" name="password"><button>Login</button></form>'

        def get_side(url, **kwargs):
            if "/login" in url:
                return self._resp(login_body, 200)
            return self._resp(status=404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("mfa" in r["type"] for r in warns)

    def test_login_form_with_totp_passes(self):
        s = self._scanner()
        login_body = '<form><input type="password"><input type="text" id="totp" placeholder="Enter OTP"><button>Login</button></form>'

        def get_side(url, **kwargs):
            if "/login" in url:
                return self._resp(login_body, 200)
            return self._resp(status=404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert not any("mfa" in r["type"] and r["status"] == "WARN" for r in results)

    def test_login_with_webauthn_passes(self):
        s = self._scanner()
        login_body = '<form><input type="password"><script>navigator.credentials.get()</script></form>'

        def get_side(url, **kwargs):
            if "/login" in url:
                return self._resp(login_body, 200)
            return self._resp(status=404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert not any("no-mfa" in r["type"] for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(status=404)):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_has_login_form(self):
        from tblue.scanner.mfa_detection import _page_has_login_form
        assert _page_has_login_form('<input type="password">') is True

    def test_no_login_form(self):
        from tblue.scanner.mfa_detection import _page_has_login_form
        assert _page_has_login_form('<input type="text">') is False

    def test_has_mfa_indicator_totp(self):
        from tblue.scanner.mfa_detection import _page_has_mfa_indicators
        assert _page_has_mfa_indicators("Enter your TOTP code") is True

    def test_has_mfa_indicator_2fa(self):
        from tblue.scanner.mfa_detection import _page_has_mfa_indicators
        assert _page_has_mfa_indicators("two-factor authentication") is True

    def test_no_mfa_indicator(self):
        from tblue.scanner.mfa_detection import _page_has_mfa_indicators
        assert _page_has_mfa_indicators("username and password") is False
