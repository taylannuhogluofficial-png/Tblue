"""Tests for HSTSPreloadScanner."""
from unittest.mock import MagicMock, patch

import pytest

from tblue.scanner.hsts_preload import HSTSPreloadScanner, _PRELOAD_MIN_MAX_AGE

URL = "https://example.com"
HTTP_URL = "http://example.com"


def _scanner():
    return HSTSPreloadScanner(MagicMock())


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.text = body
    r.status_code = status
    r.headers = headers or {}
    r.url = URL
    return r


def _good_hsts():
    return f"max-age={_PRELOAD_MIN_MAX_AGE}; includeSubDomains; preload"


# ── No HSTS header ────────────────────────────────────────────────────────────

class TestNoHSTSHeader:
    def test_missing_hsts_warns(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp("<html></html>")):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "missing" in r["type"]]
        assert warns

    def test_none_https_response_warns(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert warns


# ── HSTS max-age checks ───────────────────────────────────────────────────────

class TestMaxAge:
    def test_short_max_age_warns(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp(
            "", headers={"Strict-Transport-Security": "max-age=86400; includeSubDomains; preload"}
        )):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "short" in r["type"]]
        assert warns

    def test_max_age_zero_warns(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp(
            "", headers={"Strict-Transport-Security": "max-age=0"}
        )):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "max-age=0" in r["type"].lower()]
        assert warns

    def test_missing_max_age_warns(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp(
            "", headers={"Strict-Transport-Security": "includeSubDomains; preload"}
        )):
            results = s.scan(URL)
        warns = [r for r in results if "max-age" in r["type"].lower() and r["status"] == "WARN"]
        assert warns

    def test_sufficient_max_age_no_max_age_warn(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp(
            "", headers={"Strict-Transport-Security": _good_hsts()}
        )):
            results = s.scan(URL)
        max_age_warns = [r for r in results if "short" in r.get("type", "")]
        assert not max_age_warns


# ── includeSubDomains directive ───────────────────────────────────────────────

class TestIncludeSubDomains:
    def test_missing_include_subdomains_warns(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp(
            "", headers={"Strict-Transport-Security": f"max-age={_PRELOAD_MIN_MAX_AGE}; preload"}
        )):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "includeSubDomains" in r["type"]]
        assert warns

    def test_has_include_subdomains_no_warn(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp(
            "", headers={"Strict-Transport-Security": _good_hsts()}
        )):
            results = s.scan(URL)
        sub_warns = [r for r in results if "includeSubDomains" in r.get("type", "")]
        assert not sub_warns


# ── preload directive ─────────────────────────────────────────────────────────

class TestPreloadDirective:
    def test_missing_preload_warns(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp(
            "", headers={"Strict-Transport-Security": f"max-age={_PRELOAD_MIN_MAX_AGE}; includeSubDomains"}
        )):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "preload" in r["type"].lower()]
        assert warns

    def test_all_directives_present_passes(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp(
            "", headers={"Strict-Transport-Security": _good_hsts()}
        )):
            results = s.scan(URL)
        passes = [r for r in results if r["status"] == "PASS" and "preload-eligible" in r["type"]]
        assert passes


# ── HTTP redirect checks ──────────────────────────────────────────────────────

class TestHTTPRedirect:
    def test_http_redirects_to_https_passes(self):
        s = _scanner()

        def get_side(url, **kw):
            if url.startswith("http://"):
                return _resp("", 301, headers={"Location": "https://example.com"})
            return _resp("", headers={"Strict-Transport-Security": _good_hsts()})

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        passes = [r for r in results if r["status"] == "PASS" and "redirect" in r["type"].lower()]
        assert passes

    def test_http_redirects_to_non_https_warns(self):
        s = _scanner()

        def get_side(url, **kw):
            if url.startswith("http://"):
                return _resp("", 301, headers={"Location": "http://www.example.com"})
            return _resp("", headers={"Strict-Transport-Security": _good_hsts()})

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "non-HTTPS" in r["type"]]
        assert warns

    def test_http_accessible_without_redirect_warns(self):
        s = _scanner()

        def get_side(url, **kw):
            if url.startswith("http://"):
                return _resp("<html></html>", 200)
            return _resp("", headers={"Strict-Transport-Security": _good_hsts()})

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "no redirect" in r["type"]]
        assert warns

    def test_hsts_on_http_response_warns(self):
        s = _scanner()

        def get_side(url, **kw):
            if url.startswith("http://"):
                return _resp("", 200, headers={"Strict-Transport-Security": _good_hsts()})
            return _resp("", headers={"Strict-Transport-Security": _good_hsts()})

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "over HTTP" in r["type"]]
        assert warns

    def test_none_http_response_is_silent(self):
        s = _scanner()

        def get_side(url, **kw):
            if url.startswith("http://"):
                return None
            return _resp("", headers={"Strict-Transport-Security": _good_hsts()})

        with patch.object(s.http, "get", side_effect=get_side):
            # Should not raise
            results = s.scan(URL)
        assert results


# ── Result structure ──────────────────────────────────────────────────────────

class TestResultStructure:
    def test_result_keys_present(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp("<html></html>")):
            results = s.scan(URL)
        assert results
        for r in results:
            assert "url" in r
            assert "type" in r
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")
