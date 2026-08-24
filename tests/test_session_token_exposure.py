"""Tests for SessionTokenExposureScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.session_token_exposure import (
    SessionTokenExposureScanner, _check_token_in_url_params, _check_token_in_links,
)

URL = "https://example.com"
URL_WITH_TOKEN = "https://example.com/redirect?session_token=abc123xyz456"


class TestSessionTokenExposure:
    def _scanner(self):
        return SessionTokenExposureScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        return r

    def test_token_in_url_fails(self):
        findings = _check_token_in_url_params(URL_WITH_TOKEN)
        assert any("url" in f["type"] for f in findings)

    def test_no_token_in_url_passes(self):
        findings = _check_token_in_url_params(URL)
        assert findings == []

    def test_token_in_html_link_fails(self):
        body = '<a href="/profile?auth_token=deadbeefcafebabe">Profile</a>'
        findings = _check_token_in_links(body, URL)
        assert any("html_link" in f["type"] for f in findings)

    def test_clean_html_passes(self):
        body = '<a href="/profile">Profile</a>'
        findings = _check_token_in_links(body, URL)
        assert findings == []

    def test_bearer_in_body_fails(self):
        body = 'var authToken = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.abc";'
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("body" in r["type"] for r in fails)

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_site_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>Welcome</html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("OK", 200)):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
