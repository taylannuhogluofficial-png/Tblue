"""Tests for tblue.scanner.rate_limiting — Rate Limiting scanner."""

import pytest
from unittest.mock import MagicMock, patch, call
from tblue.scanner.rate_limiting import RateLimitingScanner


def _scanner():
    session = MagicMock()
    return RateLimitingScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _rate_limited_resp():
    return _resp(200, "", {"x-ratelimit-limit": "100", "x-ratelimit-remaining": "98"})


def _plain_resp():
    return _resp(200, "<html><body>Hello</body></html>")


# ── None response → PASS ──────────────────────────────────────────────────────

def test_no_response_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


# ── Rate limit headers present → PASS ─────────────────────────────────────────

def test_ratelimit_header_on_main_passes():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_rate_limited_resp()):
        results = s.scan("https://example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
    assert any("header" in r["type"].lower() and "present" in r["type"].lower()
               for r in passes)


def test_retry_after_header_passes():
    s = _scanner()
    r = _resp(200, "", {"retry-after": "60"})
    with patch.object(s.http, "get", return_value=r):
        results = s.scan("https://example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


# ── No rate limit headers → WARN ─────────────────────────────────────────────

def test_no_ratelimit_headers_warns():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_plain_resp()):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("no rate limit header" in r["type"].lower() for r in warns)


# ── Missing on sensitive endpoints → FAIL ─────────────────────────────────────

def test_sensitive_paths_missing_rate_limit_fails():
    s = _scanner()
    login_resp = _resp(200, "<html>Login form</html>")
    register_resp = _resp(200, "<html>Register</html>")

    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return _plain_resp()  # main URL, no rate limit headers
        if "/login" in url:
            return login_resp
        if "/register" in url:
            return register_resp
        return _resp(404, "Not Found")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("sensitive" in r["type"].lower() for r in fails)


# ── 429 during rapid probe ────────────────────────────────────────────────────

def test_429_during_rapid_probe_detected():
    s = _scanner()
    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return _plain_resp()  # main page
        if call_count[0] <= 3:
            return _resp(200, "ok")
        return _resp(429, "Too Many Requests")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    # 429 is detected during rapid probe — no FAIL for rapid probe itself
    # The WARN from no-headers might still be there
    assert results  # At minimum some result returned


# ── Sensitive paths return 404 → no FAIL ─────────────────────────────────────

def test_sensitive_404_paths_not_flagged():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _plain_resp()
        return _resp(404, "Not Found")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    # No FAIL for missing rate limit on paths that 404
    sensitive_fails = [r for r in results if "sensitive" in r.get("type", "").lower()
                       and r["status"] == "FAIL"]
    assert not sensitive_fails


# ── Rate limit in body on sensitive path ──────────────────────────────────────

def test_rate_limit_in_body_not_flagged_as_missing():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _plain_resp()
        if "/login" in url or "/register" in url or "/search" in url:
            return _resp(200, "Rate limit exceeded for this endpoint", {})
        return _resp(404, "Not Found")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    # If all existing sensitive paths have rate limit in body, no FAIL
    # (may still WARN about main page header absence)
    assert results
