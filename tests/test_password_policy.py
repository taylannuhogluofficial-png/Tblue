"""Tests for Password Policy scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestPasswordPolicyScanner:
    def _scanner(self):
        from tblue.scanner.password_policy import PasswordPolicyScanner
        return PasswordPolicyScanner(MagicMock())

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

    def test_no_form_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>no form</html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_short_minlength_fails(self):
        s = self._scanner()
        body = '<input type="password" minlength="4" name="password">'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("minlength" in r["type"].lower() for r in fails)

    def test_low_minlength_warns(self):
        s = self._scanner()
        body = '<input type="password" minlength="8" name="password">'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("minlength" in r["type"].lower() for r in warns)

    def test_short_maxlength_warns(self):
        s = self._scanner()
        body = '<input type="password" maxlength="20" name="password">'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("maxlength" in r["type"].lower() for r in warns)

    def test_missing_autocomplete_warns(self):
        s = self._scanner()
        body = '<input type="password" name="password">'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("autocomplete" in r["type"].lower() for r in warns)

    def test_forced_rotation_warns(self):
        s = self._scanner()
        body = '<input type="password"> Your password must expire every 90 days.'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("rotation" in r["type"].lower() or "rotation" in r["detail"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_find_password_inputs(self):
        from tblue.scanner.password_policy import _find_password_inputs
        body = '<input type="password" name="pass"> <input type="text" name="user">'
        inputs = _find_password_inputs(body)
        assert len(inputs) == 1

    def test_check_registration_form_good(self):
        from tblue.scanner.password_policy import _check_registration_form
        body = '<input type="password" minlength="12" maxlength="128" autocomplete="new-password">'
        findings = _check_registration_form(body, URL)
        assert findings == []

    def test_check_forced_rotation_detected(self):
        from tblue.scanner.password_policy import _check_forced_rotation
        body = "Your password will expire every 90 days."
        result = _check_forced_rotation(body, URL)
        assert result is not None

    def test_check_forced_rotation_clean(self):
        from tblue.scanner.password_policy import _check_forced_rotation
        result = _check_forced_rotation("No rotation policy here.", URL)
        assert result is None
