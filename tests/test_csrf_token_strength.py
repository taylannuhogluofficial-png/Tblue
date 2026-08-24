"""Tests for CSRF Token Strength scanner."""
from unittest.mock import MagicMock, patch
URL = "https://example.com"

class TestCSRFTokenStrengthScanner:
    def _scanner(self):
        from tblue.scanner.csrf_token_strength import CSRFTokenStrengthScanner
        return CSRFTokenStrengthScanner(MagicMock())
    def _resp(self, body="", status=200, headers=None):
        r = MagicMock(); r.text = body; r.status_code = status; r.headers = headers or {}; return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None): results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_form_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html><p>hello</p></html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_post_form_without_csrf_fails(self):
        from tblue.scanner.csrf_token_strength import _check_csrf_tokens_in_forms
        body = '<form method="post"><input type="text" name="email"></form>'
        findings = _check_csrf_tokens_in_forms(body, URL)
        assert any("missing" in f["type"] for f in findings)

    def test_post_form_with_strong_token_passes(self):
        from tblue.scanner.csrf_token_strength import _check_csrf_tokens_in_forms
        body = '<form method="post"><input name="csrf_token" value="Abc123XyzQrsTuvWxy9012345678"></form>'
        findings = _check_csrf_tokens_in_forms(body, URL)
        fails = [f for f in findings if f["status"] == "FAIL"]
        assert not fails

    def test_short_token_fails(self):
        from tblue.scanner.csrf_token_strength import _check_csrf_tokens_in_forms
        body = '<form method="post"><input name="csrf_token" value="abc123"></form>'
        findings = _check_csrf_tokens_in_forms(body, URL)
        assert any("too_short" in f["type"] for f in findings)

    def test_samesite_none_without_secure_fails(self):
        from tblue.scanner.csrf_token_strength import _check_samesite_cookie
        findings = _check_samesite_cookie({"set-cookie": "session=abc; SameSite=None"}, URL)
        assert any("samesite" in f["type"] for f in findings)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html></html>")):
            results = s.scan(URL)
        for r in results: assert r["status"] in ("PASS", "WARN", "FAIL")
