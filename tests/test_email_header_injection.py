"""Tests for Email Header Injection scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestEmailHeaderInjectionScanner:
    def _scanner(self):
        from tblue.scanner.email_header_injection import EmailHeaderInjectionScanner
        return EmailHeaderInjectionScanner(MagicMock())

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

    def test_no_contact_form_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(status=404)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_smtp_header_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(headers={"x-mailer": "PHPMailer 6.0"})):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("smtp" in r["type"] for r in warns)

    def test_contact_form_with_email_field_warns(self):
        s = self._scanner()
        body = '<form action="/contact"><input name="email" type="email"><input name="message"><button>Send</button></form>'

        def get_side(url, **kwargs):
            if "/contact" in url:
                return self._resp(body, 200)
            return self._resp(status=404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("form" in r["type"] or "inject" in r["type"] for r in warns)

    def test_contact_form_without_email_field_passes(self):
        s = self._scanner()
        body = '<form><input name="message"><button>Submit</button></form>'

        def get_side(url, **kwargs):
            if "/contact" in url:
                return self._resp(body, 200)
            return self._resp(status=404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_smtp_header(self):
        from tblue.scanner.email_header_injection import _check_smtp_headers
        result = _check_smtp_headers({"x-mailer": "PHPMailer"}, URL)
        assert result is not None

    def test_check_no_smtp_header(self):
        from tblue.scanner.email_header_injection import _check_smtp_headers
        result = _check_smtp_headers({"content-type": "text/html"}, URL)
        assert result is None

    def test_check_contact_form_with_email(self):
        from tblue.scanner.email_header_injection import _check_contact_form
        body = '<form><input name="email" type="email"><input name="message"></form>'
        findings = _check_contact_form(body, URL)
        assert len(findings) > 0

    def test_check_form_no_email_field(self):
        from tblue.scanner.email_header_injection import _check_contact_form
        body = '<form><input name="search"><button>Go</button></form>'
        findings = _check_contact_form(body, URL)
        assert findings == []
