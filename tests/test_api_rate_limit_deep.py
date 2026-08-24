"""Tests for API Rate Limit Deep scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestAPIRateLimitDeepScanner:
    def _scanner(self):
        from tblue.scanner.api_rate_limit_deep import APIRateLimitDeepScanner
        return APIRateLimitDeepScanner(MagicMock())

    def _resp(self, headers=None, status=200):
        r = MagicMock()
        r.text = "{}"
        r.status_code = status
        r.headers = headers or {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_issues_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(status=404)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_missing_rate_limit_on_login_warns(self):
        s = self._scanner()

        def get_side(url, **kwargs):
            if "/login" in url:
                return self._resp({"content-type": "text/html"})
            return self._resp(status=404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("rate" in r["type"].lower() or "auth" in r["type"].lower() for r in warns)

    def test_ip_scope_warns(self):
        s = self._scanner()
        headers = {
            "x-ratelimit-limit": "100",
            "x-ratelimit-remaining": "95",
            "x-ratelimit-scope": "ip",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("ip" in r["type"].lower() or "scope" in r["type"].lower() for r in warns)

    def test_xff_bypass_fails(self):
        s = self._scanner()
        call_count = [0]

        def get_side(url, headers=None, **kwargs):
            call_count[0] += 1
            # First call (no XFF): remaining=50; second call (with XFF): remaining=100
            if (headers or {}).get("X-Forwarded-For"):
                return self._resp({"x-ratelimit-remaining": "100", "x-ratelimit-limit": "100"})
            return self._resp({"x-ratelimit-remaining": "50", "x-ratelimit-limit": "100"})

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("bypass" in r["type"].lower() or "xff" in r["type"].lower() for r in fails)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(status=404)):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_has_rate_limit_true(self):
        from tblue.scanner.api_rate_limit_deep import _has_rate_limit
        assert _has_rate_limit({"x-ratelimit-limit": "100"}) is True

    def test_has_rate_limit_false(self):
        from tblue.scanner.api_rate_limit_deep import _has_rate_limit
        assert _has_rate_limit({"content-type": "text/html"}) is False

    def test_get_remaining(self):
        from tblue.scanner.api_rate_limit_deep import _get_remaining
        assert _get_remaining({"x-ratelimit-remaining": "42"}) == 42

    def test_get_remaining_none(self):
        from tblue.scanner.api_rate_limit_deep import _get_remaining
        assert _get_remaining({"content-type": "text/html"}) is None

    def test_check_ip_scope(self):
        from tblue.scanner.api_rate_limit_deep import _check_ip_scope
        result = _check_ip_scope({"x-ratelimit-scope": "ip"}, URL)
        assert result is not None

    def test_check_user_scope_ok(self):
        from tblue.scanner.api_rate_limit_deep import _check_ip_scope
        result = _check_ip_scope({"x-ratelimit-scope": "user"}, URL)
        assert result is None
