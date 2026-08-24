"""Tests for CORSOriginReflectionScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.cors_origin_reflection import (
    CORSOriginReflectionScanner, _check_origin_reflection, _PROBE_ORIGINS,
)

URL = "https://example.com"


class TestCORSOriginReflection:
    def _scanner(self):
        return CORSOriginReflectionScanner(MagicMock())

    def _resp(self, body="", status=200, headers=None):
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

    def test_origin_reflected_with_credentials_fails(self):
        probe = _PROBE_ORIGINS[0]
        http = MagicMock()
        http.get.return_value = self._resp(headers={
            "access-control-allow-origin": probe,
            "access-control-allow-credentials": "true",
        })
        findings = _check_origin_reflection(http, URL, probe)
        assert any("credentials" in f["type"] for f in findings)
        assert any(f["status"] == "FAIL" for f in findings)

    def test_origin_reflected_without_credentials_warns(self):
        probe = _PROBE_ORIGINS[0]
        http = MagicMock()
        http.get.return_value = self._resp(headers={
            "access-control-allow-origin": probe,
        })
        findings = _check_origin_reflection(http, URL, probe)
        assert any("reflection" in f["type"] for f in findings)
        assert any(f["status"] in ("WARN", "FAIL") for f in findings)

    def test_fixed_origin_not_reflected_passes(self):
        probe = _PROBE_ORIGINS[0]
        http = MagicMock()
        http.get.return_value = self._resp(headers={
            "access-control-allow-origin": "https://trusted.example.com",
        })
        findings = _check_origin_reflection(http, URL, probe)
        assert findings == []

    def test_no_acao_header_passes(self):
        probe = _PROBE_ORIGINS[0]
        http = MagicMock()
        http.get.return_value = self._resp(headers={})
        findings = _check_origin_reflection(http, URL, probe)
        assert findings == []

    def test_clean_site_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(
            "<html>ok</html>", headers={"access-control-allow-origin": "https://myapp.com"}
        )):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("", 404)):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
