"""Tests for APIPaginationAbuseScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.api_pagination_abuse import (
    APIPaginationAbuseScanner, _check_large_default_page, _check_limit_bypass,
)

URL = "https://example.com"


class TestAPIPaginationAbuse:
    def _scanner(self):
        return APIPaginationAbuseScanner(MagicMock())

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

    def test_large_total_count_warns(self):
        http = MagicMock()
        http.get.return_value = self._resp('{"total": 50000, "users": []}')
        findings = _check_large_default_page(http, "https://example.com")
        assert any("total" in f["type"] or "large" in f["type"] for f in findings)

    def test_small_total_count_passes(self):
        http = MagicMock()
        http.get.return_value = self._resp('{"total": 5, "items": []}')
        findings = _check_large_default_page(http, "https://example.com")
        assert findings == []

    def test_limit_bypass_fails(self):
        http = MagicMock()
        small_body = '{"items": [' + ','.join(['{"id":1}'] * 10) + ']}'
        large_body = '{"items": [' + ','.join(['{"id":1, "email":"u@example.com"}'] * 700) + ']}'
        http.get.side_effect = [
            self._resp(small_body),
            self._resp(large_body),
            self._resp(large_body),
        ]
        findings = _check_limit_bypass(http, "https://example.com")
        assert any("limit_bypass" in f["type"] for f in findings)

    def test_html_response_skipped(self):
        http = MagicMock()
        http.get.return_value = self._resp("<html><body>Login</body></html>", 200)
        findings = _check_large_default_page(http, "https://example.com")
        assert findings == []

    def test_404_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("Not Found", 404)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp('{"items": []}', 200)):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
