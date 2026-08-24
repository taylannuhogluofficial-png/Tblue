"""Tests for OAuthTokenLeakScanner."""
from unittest.mock import MagicMock, patch

import pytest

from tblue.scanner.oauth_token_leak import OAuthTokenLeakScanner

URL = "https://example.com"
URL_WITH_TOKEN = "https://example.com/callback?access_token=eyJhbGciOiJSUzI1NiJ9.abc"


def _scanner():
    return OAuthTokenLeakScanner(MagicMock())


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.text = body
    r.status_code = status
    r.headers = headers or {}
    r.url = URL
    return r


# ── URL parameter detection ───────────────────────────────────────────────────

class TestURLParams:
    def test_access_token_in_url_fails(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp("<html></html>")):
            results = s.scan(URL_WITH_TOKEN)
        fails = [r for r in results if r["status"] == "FAIL" and "token parameter in URL" in r["type"]]
        assert fails

    def test_refresh_token_in_url_fails(self):
        s = _scanner()
        url = URL + "?refresh_token=abc123def456ghi789jkl012"
        with patch.object(s.http, "get", return_value=_resp("<html></html>")):
            results = s.scan(url)
        fails = [r for r in results if r["status"] == "FAIL" and "token parameter in URL" in r["type"]]
        assert fails

    def test_api_key_in_url_fails(self):
        s = _scanner()
        url = URL + "?api_key=sk-1234567890abcdefghij"
        with patch.object(s.http, "get", return_value=_resp("<html></html>")):
            results = s.scan(url)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails

    def test_short_token_value_not_flagged(self):
        """Values shorter than _MIN_TOKEN_LENGTH should not be flagged."""
        s = _scanner()
        url = URL + "?token=abc"  # only 3 chars
        with patch.object(s.http, "get", return_value=_resp("<html></html>")):
            results = s.scan(url)
        token_fails = [r for r in results if "token parameter in URL" in r.get("type", "")]
        assert not token_fails

    def test_safe_params_not_flagged(self):
        """Non-token params should not be flagged."""
        s = _scanner()
        url = URL + "?page=1&sort=desc&filter=active"
        with patch.object(s.http, "get", return_value=_resp("<html></html>")):
            results = s.scan(url)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert not fails

    def test_no_params_skips_param_check(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp("<html></html>")):
            results = s.scan(URL)
        url_fails = [r for r in results if "token parameter in URL" in r.get("type", "")]
        assert not url_fails


# ── Page source scanning ──────────────────────────────────────────────────────

class TestPageSource:
    def test_access_token_in_href_fails(self):
        s = _scanner()
        html = '<html><a href="/logout?access_token=eyJhbGciOiJSUzI1NiJ9.longtoken">logout</a></html>'
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL" and "page source URL" in r["type"]]
        assert fails

    def test_no_token_in_source_passes(self):
        s = _scanner()
        html = "<html><body><a href='/logout'>logout</a></body></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_fragment_token_warns(self):
        s = _scanner()
        html = '<html><a href="#access_token=longaccesstoken123456">auth</a></html>'
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "fragment" in r["type"].lower()]
        assert warns

    def test_hardcoded_bearer_in_js_fails(self):
        s = _scanner()
        html = '<html><script>var auth = "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.realtoken.here";</script></html>'
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL" and "hardcoded" in r["type"].lower()]
        assert fails


# ── Null response ─────────────────────────────────────────────────────────────

class TestNullResponse:
    def test_none_response_returns_pass(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_none_response_with_token_url_still_flags_url(self):
        """URL param check happens before HTTP fetch."""
        s = _scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL_WITH_TOKEN)
        fails = [r for r in results if r["status"] == "FAIL" and "token parameter in URL" in r["type"]]
        assert fails


# ── Result structure ──────────────────────────────────────────────────────────

class TestResultStructure:
    def test_result_keys(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp("<html></html>")):
            results = s.scan(URL)
        assert results
        for r in results:
            assert "url" in r
            assert "type" in r
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")

    def test_fail_result_has_fields(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp("<html></html>")):
            results = s.scan(URL_WITH_TOKEN)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails
        assert "fields" in fails[0]
        assert fails[0]["fields"]
