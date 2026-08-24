"""Tests for Account Recovery Flow Security scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"
URL_HTTP = "http://example.com"


class TestAccountRecoveryScanner:
    def _scanner(self):
        from tblue.scanner.account_recovery import AccountRecoveryScanner
        return AccountRecoveryScanner(MagicMock())

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

    def test_http_reset_page_fails(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>reset</html>")):
            results = s.scan(URL_HTTP)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("http" in r["type"].lower() for r in fails)

    def test_security_question_warns(self):
        s = self._scanner()
        body = '<form><input name="security_question" placeholder="Mother\'s maiden name"></form>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("security" in r["type"].lower() or "question" in r["type"].lower() for r in warns)

    def test_no_expiry_fails(self):
        s = self._scanner()
        body = "<p>This link does not expire. Click to reset your password.</p>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("expir" in r["type"].lower() for r in fails)

    def test_long_expiry_warns(self):
        s = self._scanner()
        body = "<p>This link is valid for 48 hours.</p>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("expiry" in r["type"].lower() or "expir" in r["type"].lower() for r in warns)

    def test_username_enumeration_warns(self):
        s = self._scanner()
        body = "<p>No account found with that email address.</p>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("enumeration" in r["type"].lower() for r in warns)

    def test_no_issues_passes(self):
        s = self._scanner()
        body = "<p>If an account exists, a reset email was sent.</p>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_http_reset_page_fails(self):
        from tblue.scanner.account_recovery import _check_http_reset_page
        result = _check_http_reset_page("http://example.com")
        assert result is not None
        assert result["status"] == "FAIL"

    def test_check_http_reset_page_https_ok(self):
        from tblue.scanner.account_recovery import _check_http_reset_page
        assert _check_http_reset_page("https://example.com") is None

    def test_check_security_questions_detected(self):
        from tblue.scanner.account_recovery import _check_security_questions
        body = "What is your mother's maiden name?"
        result = _check_security_questions(body, URL)
        assert result is not None

    def test_check_security_questions_clean(self):
        from tblue.scanner.account_recovery import _check_security_questions
        assert _check_security_questions("Enter your email to reset.", URL) is None

    def test_check_expiry_no_expiry(self):
        from tblue.scanner.account_recovery import _check_expiry_signals
        result = _check_expiry_signals("This link never expires.", URL)
        assert result is not None
        assert result["status"] == "FAIL"

    def test_check_expiry_long(self):
        from tblue.scanner.account_recovery import _check_expiry_signals
        result = _check_expiry_signals("Link is valid for 72 hours.", URL)
        assert result is not None
        assert result["status"] == "WARN"

    def test_check_expiry_short_ok(self):
        from tblue.scanner.account_recovery import _check_expiry_signals
        assert _check_expiry_signals("Link expires in 15 minutes.", URL) is None
