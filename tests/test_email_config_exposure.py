"""Tests for Email Config Exposure scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestEmailConfigExposureScanner:
    def _scanner(self):
        from tblue.scanner.email_config_exposure import EmailConfigExposureScanner
        return EmailConfigExposureScanner(MagicMock())

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

    def test_clean_page_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>OK</html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_smtp_credentials_in_js_fails(self):
        s = self._scanner()
        body = 'var mailer = { host: "smtp.gmail.com", password: "s3cret123" };'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("smtp" in r["type"] and "cred" in r["type"] for r in fails)

    def test_smtp_host_disclosure_warns(self):
        s = self._scanner()
        body = 'const SMTP_HOST = "smtp.mailgun.org";'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("smtp" in r["type"] and "host" in r["type"] for r in warns)

    def test_mailhog_ui_exposed_fails(self):
        s = self._scanner()

        def get_side(url, **kwargs):
            if "/mailhog" in url or "/mail" in url:
                return self._resp("<html>MailHog - Inbox</html>", 200)
            return self._resp("<html>OK</html>", 200)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("mail" in r["type"] for r in fails)

    def test_smtp_header_warns(self):
        s = self._scanner()
        headers = {"x-mailer": "PHPMailer 5.2.1"}
        with patch.object(s.http, "get", return_value=self._resp("<html>OK</html>", headers=headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("smtp" in r["type"] or "mailer" in r["type"] for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_smtp_creds_detected(self):
        from tblue.scanner.email_config_exposure import _check_smtp_in_js
        findings = _check_smtp_in_js('smtp = { password: "secret123" }', URL)
        assert any("cred" in f["type"] for f in findings)

    def test_smtp_host_detected(self):
        from tblue.scanner.email_config_exposure import _check_smtp_in_js
        findings = _check_smtp_in_js('SMTP_HOST = "smtp.gmail.com"', URL)
        assert any("host" in f["type"] for f in findings)

    def test_clean_js(self):
        from tblue.scanner.email_config_exposure import _check_smtp_in_js
        assert _check_smtp_in_js("const x = 1;", URL) == []
