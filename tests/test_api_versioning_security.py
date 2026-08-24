"""Tests for API Versioning Security scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com/api/v3/users"
URL_UNVERSIONED = "https://example.com"


class TestAPIVersioningSecurityScanner:
    def _scanner(self):
        from tblue.scanner.api_versioning_security import APIVersioningSecurityScanner
        return APIVersioningSecurityScanner(MagicMock())

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
        with patch.object(s.http, "get", return_value=self._resp("OK", 404)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_deprecated_version_warns(self):
        from tblue.scanner.api_versioning_security import _check_deprecated_version_accessible
        http = MagicMock()
        r = MagicMock()
        r.status_code = 200
        r.text = '{"users": []}'
        http.get.return_value = r
        findings = _check_deprecated_version_accessible(http, "https://example.com", 3)
        assert any("deprecated" in f["type"] for f in findings)

    def test_current_version_not_flagged(self):
        from tblue.scanner.api_versioning_security import _check_deprecated_version_accessible
        http = MagicMock()
        r = MagicMock()
        r.status_code = 404
        r.text = "Not Found"
        http.get.return_value = r
        findings = _check_deprecated_version_accessible(http, "https://example.com", 1)
        assert findings == []

    def test_unversioned_endpoint_warns(self):
        from tblue.scanner.api_versioning_security import _check_unversioned_api
        http = MagicMock()
        r = MagicMock()
        r.status_code = 200
        r.text = '{"status": "ok"}'
        http.get.return_value = r
        findings = _check_unversioned_api(http, "https://example.com")
        assert any("unversioned" in f["type"] for f in findings)

    def test_version_downgrade_via_header_warns(self):
        from tblue.scanner.api_versioning_security import _check_version_downgrade_via_header
        http = MagicMock()
        r1 = MagicMock()
        r1.status_code = 200
        r1.text = '{"version": "3", "data": []}'
        r2 = MagicMock()
        r2.status_code = 200
        r2.text = '{"version": "1", "data": [{"id": 1}]}'  # different response
        http.get.side_effect = [r1, r2]
        findings = _check_version_downgrade_via_header(http, URL)
        assert any("downgrade" in f["type"] for f in findings)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("OK", 404)):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
