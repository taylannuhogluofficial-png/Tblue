"""Tests for Secret in Error Page scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestSecretInErrorPageScanner:
    def _scanner(self):
        from tblue.scanner.secret_in_error_page import SecretInErrorPageScanner
        return SecretInErrorPageScanner(MagicMock())

    def _resp(self, body="Not Found", status=404, headers=None):
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

    def test_clean_404_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("Page Not Found", 404)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_stack_trace_fails(self):
        from tblue.scanner.secret_in_error_page import _scan_body_for_secrets
        body = "Traceback (most recent call last):\n  File '/app/views.py', line 42, in get"
        findings = _scan_body_for_secrets(body, URL)
        assert any("stack_trace" in f["type"] for f in findings)

    def test_db_connection_fails(self):
        from tblue.scanner.secret_in_error_page import _scan_body_for_secrets
        body = "Error: could not connect to postgresql://admin:pass123@db.internal:5432/mydb"
        findings = _scan_body_for_secrets(body, URL)
        assert any("db_connection" in f["type"] for f in findings)

    def test_internal_path_warns(self):
        from tblue.scanner.secret_in_error_page import _scan_body_for_secrets
        body = "Template not found: /var/www/myapp/templates/index.html"
        findings = _scan_body_for_secrets(body, URL)
        assert any("internal_path" in f["type"] for f in findings)

    def test_api_key_fails(self):
        from tblue.scanner.secret_in_error_page import _scan_body_for_secrets
        body = "api_key=AKIAIOSFODNN7EXAMPLE123456 caused authentication failure"
        findings = _scan_body_for_secrets(body, URL)
        assert any("api_key" in f["type"] for f in findings)

    def test_clean_body_passes(self):
        from tblue.scanner.secret_in_error_page import _scan_body_for_secrets
        findings = _scan_body_for_secrets("<h1>Not Found</h1><p>The requested URL was not found.</p>", URL)
        assert findings == []

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("Not Found", 404)):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
