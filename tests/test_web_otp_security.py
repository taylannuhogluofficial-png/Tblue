"""Tests for WebOTPSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.web_otp_security import WebOTPSecurityScanner


def _scanner():
    s = WebOTPSecurityScanner.__new__(WebOTPSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestCodeToAnalytics:
    def test_otp_to_analytics_fails(self):
        s = _scanner()
        # _OTP_THIRD_PARTY_RE: analytics ... code within 200 non-semicolon chars
        body = "const cred = new OTPCredential()\nanalytics('auth', {code: cred.code})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_otp_code_to_analytics" in types


class TestCodeTransmitted:
    def test_otp_sent_warns(self):
        s = _scanner()
        # _OTP_SEND_RE: code before fetch within 200 non-semicolon chars
        body = "const {otp} = new OTPCredential()\nconst code = otp.code\nfetch('/verify', {body: code})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_otp_code_transmitted" in types


class TestNoAbortController:
    def test_no_abort_warns(self):
        s = _scanner()
        body = "const cred = new OTPCredential(); navigator.credentials.get({otp: {transport: ['sms']}})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_otp_no_abort_controller" in types

    def test_with_abort_passes(self):
        s = _scanner()
        body = "const ac = new AbortController(); const cred = new OTPCredential(); navigator.credentials.get({otp: {transport: ['sms']}, signal: ac.signal})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "web_otp_no_abort_controller" not in types


class TestNotUsed:
    def test_no_otp_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "web_otp_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
