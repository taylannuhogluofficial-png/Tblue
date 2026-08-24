"""Tests for OAuthImplicitFlowScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.oauth_implicit_flow import (
    OAuthImplicitFlowScanner, _check_implicit_in_discovery,
)

URL = "https://example.com"


class TestOAuthImplicitFlow:
    def _scanner(self):
        return OAuthImplicitFlowScanner(MagicMock())

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

    def test_implicit_in_discovery_fails(self):
        discovery = '{"grant_types_supported": ["authorization_code", "implicit", "refresh_token"]}'
        http = MagicMock()
        http.get.return_value = self._resp(discovery)
        findings = _check_implicit_in_discovery(http, "https://example.com")
        assert any("implicit" in f["type"] for f in findings)

    def test_implicit_in_discovery_with_pkce_warns(self):
        discovery = ('{"grant_types_supported": ["authorization_code", "implicit"], '
                     '"code_challenge_methods_supported": ["S256"]}')
        http = MagicMock()
        http.get.return_value = self._resp(discovery)
        findings = _check_implicit_in_discovery(http, "https://example.com")
        assert any("implicit" in f["type"] for f in findings)
        if findings:
            assert findings[0]["status"] in ("WARN", "FAIL")

    def test_no_implicit_in_discovery_passes(self):
        discovery = '{"grant_types_supported": ["authorization_code", "refresh_token"]}'
        http = MagicMock()
        http.get.return_value = self._resp(discovery)
        findings = _check_implicit_in_discovery(http, "https://example.com")
        assert findings == []

    def test_implicit_flow_in_page_warns(self):
        body = '<a href="/oauth/authorize?response_type=token&client_id=abc">Login</a>'
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("implicit" in r["type"] for r in warns)

    def test_no_oauth_clean_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>Normal page</html>", 200)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("", 404)):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
