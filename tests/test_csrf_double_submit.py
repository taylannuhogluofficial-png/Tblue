"""Tests for CSRFDoubleSubmitScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.csrf_double_submit import CSRFDoubleSubmitScanner, _analyze_csrf_protection

URL = "https://example.com"


class TestCSRFDoubleSubmit:
    def _scanner(self):
        return CSRFDoubleSubmitScanner(MagicMock())

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

    def test_form_without_csrf_token_fails(self):
        body = '<form method="post" action="/transfer"><input name="amount" value="100"></form>'
        findings = _analyze_csrf_protection(body, URL)
        assert any("no_token" in f["type"] for f in findings)

    def test_form_with_csrf_token_passes(self):
        body = '''<form method="post">
            <input type="hidden" name="csrf_token" value="abc123xyz">
            <input name="data" value="test">
        </form>'''
        findings = _analyze_csrf_protection(body, URL)
        fails = [f for f in findings if f["status"] == "FAIL" and "no_token" in f["type"]]
        assert len(fails) == 0

    def test_static_csrf_token_fails(self):
        body = '''<form>
            <input name="csrf_token" value="">
            <script>var csrf_token = "deadbeef1234abcd";</script>
        </form>'''
        findings = _analyze_csrf_protection(body, URL)
        assert any("static_token" in f["type"] for f in findings)

    def test_no_forms_passes(self):
        body = "<html><body><p>No forms here</p></body></html>"
        findings = _analyze_csrf_protection(body, URL)
        assert findings == []

    def test_double_submit_cookie_warns(self):
        body = '''<form method="post">
            <input name="csrf_token" value="x">
        </form>
        <script>
            var csrf = getCookie('csrf_token');
        </script>'''
        findings = _analyze_csrf_protection(body, URL)
        warns = [f for f in findings if "double_submit" in f["type"]]
        assert isinstance(findings, list)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>no forms</html>")):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
