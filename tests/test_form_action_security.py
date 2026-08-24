"""Tests for Form Action Security scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestFormActionSecurityScanner:
    def _scanner(self):
        from tblue.scanner.form_action_security import FormActionSecurityScanner
        return FormActionSecurityScanner(MagicMock())

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

    def test_no_forms_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html><p>no form</p></html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_http_action_on_https_fails(self):
        s = self._scanner()
        body = '<form action="http://example.com/submit"><input type="text"></form>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("http" in r["type"].lower() for r in fails)

    def test_javascript_action_fails(self):
        s = self._scanner()
        body = '<form action="javascript:void(0)"><input type="submit"></form>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("javascript" in r["type"].lower() for r in fails)

    def test_external_domain_action_warns(self):
        s = self._scanner()
        body = '<form action="https://evil.com/collect"><input type="text"></form>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("external" in r["type"].lower() for r in warns)

    def test_login_form_no_csrf_warns(self):
        s = self._scanner()
        body = '<form action="/login"><input type="password" name="password"><input type="submit"></form>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("csrf" in r["type"].lower() for r in warns)

    def test_login_form_with_csrf_ok(self):
        s = self._scanner()
        body = ('<form action="/login">'
                '<input type="password" name="password">'
                '<input type="hidden" name="csrf_token" value="abc123">'
                '</form>')
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        assert not any("csrf" in r["type"].lower() for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_form_http_action(self):
        from tblue.scanner.form_action_security import _check_form
        form = '<form action="http://example.com/submit"><input type="text"></form>'
        findings = _check_form(form, "https://example.com", "example.com")
        assert any("http" in f["type"].lower() for f in findings)

    def test_check_form_javascript_action(self):
        from tblue.scanner.form_action_security import _check_form
        form = '<form action="javascript:alert(1)"><input type="submit"></form>'
        findings = _check_form(form, URL, "example.com")
        assert any("javascript" in f["type"].lower() for f in findings)

    def test_check_form_clean(self):
        from tblue.scanner.form_action_security import _check_form
        form = ('<form action="/search">'
                '<input type="text" name="q">'
                '<input type="hidden" name="csrf_token" value="x">'
                '</form>')
        findings = _check_form(form, URL, "example.com")
        assert findings == []
