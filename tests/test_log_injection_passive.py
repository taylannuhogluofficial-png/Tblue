"""Tests for Log Injection Passive scanner."""
from unittest.mock import MagicMock, patch
URL = "https://example.com"

class TestLogInjectionPassiveScanner:
    def _scanner(self):
        from tblue.scanner.log_injection_passive import LogInjectionPassiveScanner
        return LogInjectionPassiveScanner(MagicMock())
    def _resp(self, body="OK", status=200, headers=None):
        r = MagicMock(); r.text = body; r.status_code = status; r.headers = headers or {}; return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None): results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_site_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>OK</html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_crlf_header_injection_fails(self):
        from tblue.scanner.log_injection_passive import _check_crlf_injection
        http = MagicMock(); r = MagicMock(); r.status_code = 200; r.text = "OK"
        r.headers = {"x-log-injected": "true", "content-type": "text/html"}
        http.get.return_value = r
        findings = _check_crlf_injection(http, URL)
        assert any("crlf" in f["type"] for f in findings)

    def test_no_crlf_reflection_passes(self):
        from tblue.scanner.log_injection_passive import _check_crlf_injection
        http = MagicMock(); r = MagicMock(); r.status_code = 404; r.text = "Not Found"; r.headers = {}
        http.get.return_value = r
        findings = _check_crlf_injection(http, URL)
        assert findings == []

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>clean</html>")):
            results = s.scan(URL)
        for r in results: assert r["status"] in ("PASS", "WARN", "FAIL")
