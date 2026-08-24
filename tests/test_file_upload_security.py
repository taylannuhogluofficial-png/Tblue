"""Tests for File Upload Security scanner."""
from unittest.mock import MagicMock, patch
URL = "https://example.com"

class TestFileUploadSecurityScanner:
    def _scanner(self):
        from tblue.scanner.file_upload_security import FileUploadSecurityScanner
        return FileUploadSecurityScanner(MagicMock())
    def _resp(self, body="OK", status=200, headers=None):
        r = MagicMock(); r.text = body; r.status_code = status; r.headers = headers or {}; return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None): results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_file_input_no_accept_warns(self):
        from tblue.scanner.file_upload_security import _check_upload_forms
        body = '<form enctype="multipart/form-data"><input type="file" name="doc"></form>'
        findings = _check_upload_forms(body, URL)
        assert any("no_accept" in f["type"] for f in findings)

    def test_dangerous_accept_type_fails(self):
        from tblue.scanner.file_upload_security import _check_upload_forms
        body = '<form enctype="multipart/form-data"><input type="file" name="f" accept=".php,.jpg"></form>'
        findings = _check_upload_forms(body, URL)
        assert any("dangerous" in f["type"] for f in findings)

    def test_safe_accept_type_passes(self):
        from tblue.scanner.file_upload_security import _check_upload_forms
        body = '<form enctype="multipart/form-data"><input type="file" name="f" accept=".jpg,.png,.gif"></form>'
        findings = _check_upload_forms(body, URL)
        fails = [f for f in findings if f["status"] == "FAIL"]
        assert not fails

    def test_upload_endpoint_warns(self):
        from tblue.scanner.file_upload_security import _check_upload_endpoint_exposed
        http = MagicMock(); r = MagicMock(); r.status_code = 200; r.text = "Upload"
        http.get.return_value = r
        findings = _check_upload_endpoint_exposed(http, "https://example.com")
        assert any("endpoint" in f["type"] for f in findings)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>no form</html>", 404)):
            results = s.scan(URL)
        for r in results: assert r["status"] in ("PASS", "WARN", "FAIL")
