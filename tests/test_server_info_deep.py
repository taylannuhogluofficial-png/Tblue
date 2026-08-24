"""Tests for Server Info Deep scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestServerInfoDeepScanner:
    def _scanner(self):
        from tblue.scanner.server_info_deep import ServerInfoDeepScanner
        return ServerInfoDeepScanner(MagicMock())

    def _resp(self, headers=None, body="", status=200):
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

    def test_no_issues_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"content-type": "text/html"})):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_versioned_server_header_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"server": "nginx/1.21.6"})):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("server" in r["type"] for r in warns)

    def test_x_powered_by_version_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"x-powered-by": "PHP/8.1.0"})):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("powered" in r["type"] or "x_powered" in r["type"] for r in warns)

    def test_internal_host_header_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"x-backend-server": "internal-srv-01"})):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("internal" in r["type"] for r in warns)

    def test_stack_trace_in_body_warns(self):
        s = self._scanner()
        body = "Traceback (most recent call last):\n  File 'app.py', line 42"

        def get_side(url, **kwargs):
            return self._resp({}, body=body)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("stack" in r["type"] for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_version_in_header(self):
        from tblue.scanner.server_info_deep import _check_version_in_header
        result = _check_version_in_header("server", "nginx/1.21.6", URL)
        assert result is not None

    def test_check_no_version(self):
        from tblue.scanner.server_info_deep import _check_version_in_header
        result = _check_version_in_header("server", "nginx", URL)
        assert result is None

    def test_check_internal_host(self):
        from tblue.scanner.server_info_deep import _check_internal_host_headers
        findings = _check_internal_host_headers({"x-backend-server": "srv01"}, URL)
        assert len(findings) > 0

    def test_check_no_internal_host(self):
        from tblue.scanner.server_info_deep import _check_internal_host_headers
        findings = _check_internal_host_headers({"content-type": "text/html"}, URL)
        assert findings == []

    def test_check_stack_trace(self):
        from tblue.scanner.server_info_deep import _check_error_page
        body = "Traceback (most recent call last):\n  File app.py line 10"
        findings = _check_error_page(body, URL)
        assert any("stack" in f["type"] for f in findings)

    def test_check_file_path(self):
        from tblue.scanner.server_info_deep import _check_error_page
        body = "Error in /var/www/html/app/controllers/main.py at line 99"
        findings = _check_error_page(body, URL)
        assert any("path" in f["type"] or "file" in f["type"] for f in findings)
