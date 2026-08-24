"""Tests for AutocompleteSecurityScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.autocomplete_security import (
    AutocompleteSecurityScanner, _check_password_autocomplete,
    _check_cc_autocomplete, _check_token_autocomplete,
)

URL = "https://example.com"


class TestAutocompleteSecurity:
    def _scanner(self):
        return AutocompleteSecurityScanner(MagicMock())

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

    def test_password_without_autocomplete_warns(self):
        body = '<input type="password" name="pass" placeholder="Password">'
        findings = _check_password_autocomplete(body, URL)
        assert any("password" in f["type"] for f in findings)

    def test_password_with_autocomplete_new_passes(self):
        body = '<input type="password" name="pass" autocomplete="new-password">'
        findings = _check_password_autocomplete(body, URL)
        assert findings == []

    def test_password_with_autocomplete_off_passes(self):
        body = '<input type="password" name="pass" autocomplete="off">'
        findings = _check_password_autocomplete(body, URL)
        assert findings == []

    def test_cc_number_without_autocomplete_warns(self):
        body = '<input type="text" name="card_number" placeholder="Card number">'
        findings = _check_cc_autocomplete(body, URL)
        assert any("credit_card" in f["type"] for f in findings)

    def test_api_key_field_warns(self):
        body = '<input type="text" name="api_key" placeholder="Enter API key">'
        findings = _check_token_autocomplete(body, URL)
        assert any("api_key" in f["type"] for f in findings)

    def test_no_sensitive_fields_passes(self):
        body = "<html><body><input type='text' name='username'></body></html>"
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_form_autocomplete_off_passes(self):
        body = '<form autocomplete="off"><input type="password" name="pass"></form>'
        findings = _check_password_autocomplete(body, URL)
        assert findings == []

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("OK")):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
