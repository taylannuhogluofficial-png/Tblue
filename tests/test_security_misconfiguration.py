"""Tests for Security Misconfiguration scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestSecurityMisconfigurationScanner:
    def _scanner(self):
        from tblue.scanner.security_misconfiguration import SecurityMisconfigurationScanner
        return SecurityMisconfigurationScanner(MagicMock())

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

    def test_version_comment_warns(self):
        s = self._scanner()
        body = "<html><!-- version 2.3.1 --><body>Hello</body></html>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("version" in r["type"] for r in warns)

    def test_debug_comment_warns(self):
        s = self._scanner()
        body = "<html><!-- TODO: remove before prod --><body></body></html>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("comment" in r["type"] or "sensitive" in r["type"] for r in warns)

    def test_internal_ip_in_body_warns(self):
        s = self._scanner()
        body = "<html>Internal server at 192.168.1.50</html>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("internal_ip" in r["type"] for r in warns)

    def test_backup_file_fails(self):
        s = self._scanner()

        def get_side(url, **kwargs):
            if ".bak" in url:
                return self._resp("<?php $db_password = 'supersecretpassword123'; $db_host = 'localhost'; ?>", 200)
            return self._resp("<html>OK</html>", 200)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("backup" in r["type"] for r in fails)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_html_comments_version(self):
        from tblue.scanner.security_misconfiguration import _check_html_comments
        findings = _check_html_comments("<!-- version 1.2.3 -->", URL)
        assert any("version" in f["type"] for f in findings)

    def test_check_html_comments_clean(self):
        from tblue.scanner.security_misconfiguration import _check_html_comments
        assert _check_html_comments("<html>OK</html>", URL) == []

    def test_check_internal_ip_body(self):
        from tblue.scanner.security_misconfiguration import _check_internal_ip_leak
        result = _check_internal_ip_leak("server at 10.0.0.1", {}, URL)
        assert result is not None

    def test_check_internal_ip_clean(self):
        from tblue.scanner.security_misconfiguration import _check_internal_ip_leak
        assert _check_internal_ip_leak("Hello world", {}, URL) is None
