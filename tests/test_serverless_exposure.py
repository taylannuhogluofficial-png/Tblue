"""Tests for Serverless Exposure scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestServerlessExposureScanner:
    def _scanner(self):
        from tblue.scanner.serverless_exposure import ServerlessExposureScanner
        return ServerlessExposureScanner(MagicMock())

    def _resp(self, body="", headers=None, status=200):
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

    def test_no_platform_headers_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(headers={"content-type": "text/html"})):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_vercel_header_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(headers={"x-vercel-id": "sfo1::abc123"})):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("vercel" in r["type"].lower() or "serverless" in r["type"].lower() for r in warns)

    def test_netlify_header_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(headers={"x-nf-request-id": "req-123"})):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("netlify" in r["type"].lower() or "serverless" in r["type"].lower() for r in warns)

    def test_env_file_exposed_fails(self):
        s = self._scanner()
        env_body = "AWS_ACCESS_KEY_ID=AKIA...\nAWS_SECRET_ACCESS_KEY=abc123\n"

        def get_side(url, **kwargs):
            if ".env" in url and "local" not in url and "production" not in url:
                return self._resp(body=env_body, status=200)
            return self._resp(status=404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("env" in r["type"].lower() or "config" in r["type"].lower()
                   or "environment" in r["type"].lower() for r in fails)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_serverless_headers_vercel(self):
        from tblue.scanner.serverless_exposure import _check_serverless_headers
        findings = _check_serverless_headers({"x-vercel-cache": "HIT"}, URL)
        assert len(findings) > 0
        assert "vercel" in findings[0]["type"].lower()

    def test_check_serverless_headers_clean(self):
        from tblue.scanner.serverless_exposure import _check_serverless_headers
        findings = _check_serverless_headers({"content-type": "text/html"}, URL)
        assert findings == []

    def test_env_disclosure_regex(self):
        from tblue.scanner.serverless_exposure import _ENV_DISCLOSURE_RE
        assert _ENV_DISCLOSURE_RE.search("AWS_SECRET_ACCESS_KEY=abc")
        assert _ENV_DISCLOSURE_RE.search("VERCEL_TOKEN=xyz")
        assert not _ENV_DISCLOSURE_RE.search("var x = 1;")
