"""Tests for Host Header Injection scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestHostHeaderInjectionScanner:
    def _scanner(self):
        from tblue.scanner.host_header_injection import HostHeaderInjectionScanner
        return HostHeaderInjectionScanner(MagicMock())

    def _resp(self, body="OK", status=200, headers=None):
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

    def test_clean_site_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>Welcome</html>", 404)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_probe_host_reflected_fails(self):
        from tblue.scanner.host_header_injection import _check_host_reflected_in_body, _PROBE_HOST
        http = MagicMock()
        r = MagicMock()
        r.status_code = 200
        r.text = f"Reset your password at https://{_PROBE_HOST}/reset"
        r.headers = {}
        http.get.return_value = r
        findings = _check_host_reflected_in_body(http, URL)
        assert any("reflected_in_body" in f["type"] for f in findings)

    def test_probe_host_in_redirect_fails(self):
        from tblue.scanner.host_header_injection import _check_host_reflected_in_body, _PROBE_HOST
        http = MagicMock()
        r = MagicMock()
        r.status_code = 302
        r.text = ""
        r.headers = {"location": f"https://{_PROBE_HOST}/redirect"}
        http.get.return_value = r
        findings = _check_host_reflected_in_body(http, URL)
        assert any("redirect" in f["type"] for f in findings)

    def test_host_not_reflected_passes(self):
        from tblue.scanner.host_header_injection import _check_host_reflected_in_body
        http = MagicMock()
        r = MagicMock()
        r.status_code = 200
        r.text = "Welcome to example.com — reset your password here."
        r.headers = {}
        http.get.return_value = r
        findings = _check_host_reflected_in_body(http, URL)
        assert findings == []

    def test_password_reset_page_warns(self):
        from tblue.scanner.host_header_injection import _check_password_reset_paths
        http = MagicMock()
        r = MagicMock()
        r.status_code = 200
        r.text = "<form>Reset your password</form>"
        http.get.return_value = r
        findings = _check_password_reset_paths(http, "https://example.com")
        assert any("password_reset" in f["type"] for f in findings)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("OK", 404)):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
