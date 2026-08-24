"""Tests for CORS Max-Age Deep scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestCORSMaxAgeDeepScanner:
    def _scanner(self):
        from tblue.scanner.cors_max_age_deep import CORSMaxAgeDeepScanner
        return CORSMaxAgeDeepScanner(MagicMock())

    def _resp(self, headers=None):
        r = MagicMock()
        r.text = ""
        r.status_code = 200
        r.headers = headers or {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_cors_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"content-type": "text/html"})):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_excessive_max_age_warns(self):
        s = self._scanner()
        headers = {
            "access-control-allow-origin": "https://trusted.com",
            "access-control-max-age": "86401",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("max-age" in r["type"] for r in warns)

    def test_long_max_age_with_delete_warns(self):
        s = self._scanner()
        headers = {
            "access-control-allow-origin": "https://trusted.com",
            "access-control-max-age": "7200",
            "access-control-allow-methods": "GET, POST, DELETE",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("dangerous" in r["type"] or "method" in r["type"] for r in warns)

    def test_reasonable_max_age_passes(self):
        s = self._scanner()
        headers = {
            "access-control-allow-origin": "https://trusted.com",
            "access-control-max-age": "300",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_excessive_max_age(self):
        from tblue.scanner.cors_max_age_deep import _check_cors_max_age
        headers = {"access-control-allow-origin": "*", "access-control-max-age": "86401"}
        findings = _check_cors_max_age(headers, URL)
        assert any("excessive" in f["type"] or "above" in f["type"] for f in findings)

    def test_check_reasonable_max_age(self):
        from tblue.scanner.cors_max_age_deep import _check_cors_max_age
        headers = {"access-control-allow-origin": "*", "access-control-max-age": "300"}
        findings = _check_cors_max_age(headers, URL)
        assert findings == []

    def test_check_no_cors_no_findings(self):
        from tblue.scanner.cors_max_age_deep import _check_cors_max_age
        findings = _check_cors_max_age({"content-type": "text/html"}, URL)
        assert findings == []
