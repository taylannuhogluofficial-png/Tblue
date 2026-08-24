"""Tests for HSTS Deep Analysis scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"
HTTP_URL = "http://example.com"


class TestHSTSDeepAnalysisScanner:
    def _scanner(self):
        from tblue.scanner.hsts_deep_analysis import HSTSDeepAnalysisScanner
        return HSTSDeepAnalysisScanner(MagicMock())

    def _resp(self, headers=None, status=200):
        r = MagicMock()
        r.text = ""
        r.status_code = status
        r.headers = headers or {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_missing_hsts_on_https_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"content-type": "text/html"})):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("missing" in r["type"] for r in warns)

    def test_missing_hsts_on_http_no_warn(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"content-type": "text/html"})):
            results = s.scan(HTTP_URL)
        assert not any("missing" in r["type"] for r in results)

    def test_hsts_on_http_warns(self):
        s = self._scanner()
        headers = {"strict-transport-security": "max-age=31536000; includeSubDomains"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(HTTP_URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("http" in r["type"] for r in warns)

    def test_short_max_age_fails(self):
        s = self._scanner()
        headers = {"strict-transport-security": "max-age=3600"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        assert any(r["status"] in ("FAIL", "WARN") and "max-age" in r["type"] for r in results)

    def test_missing_includesubdomains_warns(self):
        s = self._scanner()
        headers = {"strict-transport-security": "max-age=31536000"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("includesubdomains" in r["type"] for r in warns)

    def test_missing_preload_warns(self):
        s = self._scanner()
        headers = {"strict-transport-security": "max-age=31536000; includeSubDomains"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("preload" in r["type"] for r in warns)

    def test_full_hsts_passes(self):
        s = self._scanner()
        headers = {"strict-transport-security": "max-age=31536000; includeSubDomains; preload"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)
        assert not any(r["status"] in ("WARN", "FAIL") for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_parse_hsts_full(self):
        from tblue.scanner.hsts_deep_analysis import _parse_hsts
        d = _parse_hsts("max-age=31536000; includeSubDomains; preload")
        assert d["max-age"] == 31536000
        assert "includesubdomains" in d
        assert "preload" in d

    def test_parse_hsts_short(self):
        from tblue.scanner.hsts_deep_analysis import _parse_hsts
        d = _parse_hsts("max-age=3600")
        assert d["max-age"] == 3600

    def test_check_hsts_missing(self):
        from tblue.scanner.hsts_deep_analysis import _check_hsts_header
        findings = _check_hsts_header({}, URL, is_https=True)
        assert any("missing" in f["type"] for f in findings)

    def test_check_hsts_on_http(self):
        from tblue.scanner.hsts_deep_analysis import _check_hsts_header
        headers = {"strict-transport-security": "max-age=31536000"}
        findings = _check_hsts_header(headers, HTTP_URL, is_https=False)
        assert any("http" in f["type"] for f in findings)
