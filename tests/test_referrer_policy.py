"""Tests for ReferrerPolicyScanner."""
from unittest.mock import MagicMock, patch

import pytest

from tblue.scanner.referrer_policy import ReferrerPolicyScanner

URL = "https://example.com"


def _scanner():
    return ReferrerPolicyScanner(MagicMock())


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.text = body
    r.status_code = status
    r.headers = headers or {}
    r.url = URL
    return r


# ── Header presence ───────────────────────────────────────────────────────────

class TestHeaderPresence:
    def test_missing_header_warns(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp("<html></html>")):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "missing" in r["type"]]
        assert warns

    def test_none_response_returns_pass(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_header_present_no_extra_missing_warn(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp(
            "<html></html>", headers={"Referrer-Policy": "strict-origin"}
        )):
            results = s.scan(URL)
        missing_warns = [r for r in results if "missing" in r.get("type", "")]
        assert not missing_warns


# ── Policy safety classification ──────────────────────────────────────────────

class TestPolicySafety:
    def test_unsafe_url_fails(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp(
            "<html></html>", headers={"Referrer-Policy": "unsafe-url"}
        )):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails

    def test_no_referrer_when_downgrade_warns(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp(
            "<html></html>", headers={"Referrer-Policy": "no-referrer-when-downgrade"}
        )):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "weak" in r["type"]]
        assert warns

    def test_strict_origin_passes(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp(
            "<html></html>", headers={"Referrer-Policy": "strict-origin"}
        )):
            results = s.scan(URL)
        passes = [r for r in results if r["status"] == "PASS"]
        assert passes

    def test_no_referrer_passes(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp(
            "<html></html>", headers={"Referrer-Policy": "no-referrer"}
        )):
            results = s.scan(URL)
        passes = [r for r in results if r["status"] == "PASS"]
        assert passes

    def test_strict_origin_when_cross_origin_passes(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp(
            "<html></html>",
            headers={"Referrer-Policy": "strict-origin-when-cross-origin"}
        )):
            results = s.scan(URL)
        passes = [r for r in results if r["status"] == "PASS"]
        assert passes

    def test_origin_acceptable(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp(
            "<html></html>", headers={"Referrer-Policy": "origin"}
        )):
            results = s.scan(URL)
        # Should have PASS for 'origin' (acceptable)
        passes = [r for r in results if r["status"] == "PASS"]
        assert passes
        # Should NOT have FAIL
        fails = [r for r in results if r["status"] == "FAIL"]
        assert not fails

    def test_unrecognized_policy_warns(self):
        s = _scanner()
        with patch.object(s.http, "get", return_value=_resp(
            "<html></html>", headers={"Referrer-Policy": "made-up-value-123"}
        )):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN" and "unrecognized" in r["type"]]
        assert warns


# ── Meta tag extraction ───────────────────────────────────────────────────────

class TestMetaTag:
    def test_meta_referrer_unsafe_url_fails(self):
        s = _scanner()
        html = "<html><head><meta name='referrer' content='unsafe-url'></head></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails

    def test_meta_referrer_no_referrer_passes(self):
        s = _scanner()
        html = "<html><head><meta name='referrer' content='no-referrer'></head></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        passes = [r for r in results if r["status"] == "PASS"]
        assert passes

    def test_meta_referrer_without_header_found(self):
        """Meta referrer counts as having a policy (no 'missing' warning)."""
        s = _scanner()
        html = "<html><head><meta name='referrer' content='strict-origin'></head></html>"
        with patch.object(s.http, "get", return_value=_resp(html)):
            results = s.scan(URL)
        missing_warns = [r for r in results if "missing" in r.get("type", "")]
        assert not missing_warns


# ── Policy inconsistency ──────────────────────────────────────────────────────

class TestInconsistency:
    def test_inconsistent_header_and_meta_warns(self):
        """Header is safe, meta tag is unsafe → inconsistency warning."""
        s = _scanner()
        html = "<html><head><meta name='referrer' content='unsafe-url'></head></html>"
        with patch.object(s.http, "get", return_value=_resp(
            html, headers={"Referrer-Policy": "no-referrer"}
        )):
            results = s.scan(URL)
        inconsistent = [r for r in results if "inconsistent" in r.get("type", "")]
        assert inconsistent

    def test_consistent_header_and_meta_no_warn(self):
        """Both header and meta safe → no inconsistency warning."""
        s = _scanner()
        html = "<html><head><meta name='referrer' content='no-referrer'></head></html>"
        with patch.object(s.http, "get", return_value=_resp(
            html, headers={"Referrer-Policy": "no-referrer"}
        )):
            results = s.scan(URL)
        inconsistent = [r for r in results if "inconsistent" in r.get("type", "")]
        assert not inconsistent


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
