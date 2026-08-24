"""Tests for HTTPMethodTamperingScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.http_method_tampering import (
    HTTPMethodTamperingScanner, _check_method_override_header, _check_method_param,
)

URL = "https://example.com"


class TestHTTPMethodTampering:
    def _scanner(self):
        return HTTPMethodTamperingScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_method_override_accepted_fails(self):
        http = MagicMock()
        http.get.return_value = self._resp('{"status": "deleted", "success": true}', 200)
        findings = _check_method_override_header(http, "https://example.com", "/api/users")
        assert any("override" in f["type"] for f in findings)

    def test_method_param_delete_accepted_fails(self):
        http = MagicMock()
        http.get.side_effect = [
            self._resp('{"success": true, "deleted": 1}', 200),
            self._resp('{"success": true, "deleted": 1}', 200),
        ]
        findings = _check_method_param(http, "https://example.com", "/api/users")
        assert any("param_tunneling" in f["type"] for f in findings)

    def test_clean_api_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp('{"users": []}', 200)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_404_on_all_paths_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("Not Found", 404)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("OK", 200)):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
