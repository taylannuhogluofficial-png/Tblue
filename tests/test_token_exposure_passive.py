"""Tests for Token Exposure Passive scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"
URL_WITH_TOKEN = "https://example.com/callback?access_token=abc123def456ghi789jkl"
URL_WITH_JWT = "https://example.com/auth?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123def456ghi789jkl"


class TestTokenExposurePassiveScanner:
    def _scanner(self):
        from tblue.scanner.token_exposure_passive import TokenExposurePassiveScanner
        return TokenExposurePassiveScanner(MagicMock())

    def _resp(self, body="", headers=None, status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        return r

    def test_clean_url_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_access_token_in_url_fails(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL_WITH_TOKEN)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("url" in r["type"] and "token" in r["type"] for r in fails)

    def test_jwt_in_url_fails(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL_WITH_JWT)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("jwt" in r["type"] for r in fails)

    def test_token_in_response_header_warns(self):
        s = self._scanner()
        headers = {"x-api-key": "abc123def456ghi789jkl"}
        with patch.object(s.http, "get", return_value=self._resp(headers=headers)):
            results = s.scan(URL)
        found = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("header" in r["type"] and "token" in r["type"] for r in found)

    def test_no_response(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_sensitive_param_in_url(self):
        from tblue.scanner.token_exposure_passive import _check_sensitive_params_in_url
        findings = _check_sensitive_params_in_url(
            "https://example.com?access_token=abc123def456ghi789jkl0mn"
        )
        assert any("url" in f["type"] for f in findings)

    def test_clean_url_no_findings(self):
        from tblue.scanner.token_exposure_passive import _check_sensitive_params_in_url
        assert _check_sensitive_params_in_url("https://example.com?page=1") == []

    def test_jwt_in_url(self):
        from tblue.scanner.token_exposure_passive import _check_sensitive_params_in_url
        findings = _check_sensitive_params_in_url(URL_WITH_JWT)
        assert any("jwt" in f["type"] for f in findings)

    def test_token_in_response_header(self):
        from tblue.scanner.token_exposure_passive import _check_token_in_response_headers
        findings = _check_token_in_response_headers(
            {"x-api-key": "abc123def456ghi789jkl"}, URL
        )
        assert any("header" in f["type"] for f in findings)
