"""Tests for tblue.scanner.api_security_headers — API security headers scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.api_security_headers import APISecurityHeadersScanner


def _scanner():
    session = MagicMock()
    return APISecurityHeadersScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _good_api_resp():
    return _resp(200, '{"data":[]}', {
        "content-type": "application/json; charset=utf-8",
        "x-content-type-options": "nosniff",
        "strict-transport-security": "max-age=31536000",
        "cache-control": "no-store, private",
    })


# ── None response → PASS ──────────────────────────────────────────────────────

def test_no_response_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


# ── No API endpoint → PASS ────────────────────────────────────────────────────

def test_no_api_endpoint_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(404, "Not Found")):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)
    assert any("no api" in r["type"].lower() for r in results if r["status"] == "PASS")


# ── Missing X-Content-Type-Options → WARN ─────────────────────────────────────

def test_missing_xcto_warns():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        if "/api" in url:
            return _resp(200, '{"data":[]}', {
                "content-type": "application/json; charset=utf-8",
                "cache-control": "no-store",
                # No x-content-type-options
            })
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("x-content-type-options" in r["type"].lower() for r in warns)


# ── Missing Cache-Control → WARN ──────────────────────────────────────────────

def test_missing_cache_control_warns():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        if "/api" in url:
            return _resp(200, '{"data":[]}', {
                "content-type": "application/json; charset=utf-8",
                "x-content-type-options": "nosniff",
                # No cache-control
            })
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("cache-control" in r["type"].lower() or "cache" in r["type"].lower()
               for r in warns)


# ── Cacheable API response → WARN ─────────────────────────────────────────────

def test_cacheable_api_warns():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        if "/api" in url:
            return _resp(200, '{"data":[]}', {
                "content-type": "application/json; charset=utf-8",
                "x-content-type-options": "nosniff",
                "cache-control": "public, max-age=86400",  # Too permissive
            })
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("cache" in r["type"].lower() for r in warns)


# ── Stack trace in error response → FAIL ─────────────────────────────────────

def test_stack_trace_in_error_fails():
    s = _scanner()
    error_body = '{"error":"NullPointerException","stack":"at com.example.App.main(App.java:42)"}'
    discovery_resp = _resp(200, '{"ok":true}', {"content-type": "application/json; charset=utf-8"})
    error_resp = _resp(500, error_body, {"content-type": "application/json"})

    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        if "/api" in url:
            # First call (discovery) returns 200; second call returns 500 with stack trace
            return discovery_resp if call_count[0] <= 2 else error_resp
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("stack trace" in r["type"].lower() for r in fails)


# ── DB error in response → FAIL ───────────────────────────────────────────────

def test_db_error_in_response_fails():
    s = _scanner()
    db_error_body = '{"error":"ERROR: relation \"users\" does not exist (PostgreSQL)"}'

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        if "/api" in url:
            return _resp(400, db_error_body, {"content-type": "application/json"})
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("database" in r["type"].lower() or "db" in r["type"].lower() for r in fails)


# ── Server version in header → WARN ──────────────────────────────────────────

def test_server_version_warns():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        if "/api" in url:
            return _resp(200, '{"ok":true}', {
                "content-type": "application/json; charset=utf-8",
                "x-content-type-options": "nosniff",
                "cache-control": "no-store",
                "server": "nginx/1.22.1",
            })
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("server version" in r["type"].lower() for r in warns)


# ── Deprecated API version accessible → WARN ─────────────────────────────────

def test_deprecated_api_warns():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        if "/api/v0" in url or "/api/beta" in url or "/api/alpha" in url:
            return _resp(200, '{"deprecated":true}', {"content-type": "application/json"})
        if "/api" in url:
            return _resp(200, '{"data":[]}', {
                "content-type": "application/json; charset=utf-8",
                "x-content-type-options": "nosniff",
                "cache-control": "no-store, private",
            })
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("deprecated" in r["type"].lower() for r in warns)


# ── Good API → PASS ──────────────────────────────────────────────────────────

def test_well_configured_api_passes():
    s = _scanner()
    deprecated_patterns = ("/v0", "/beta", "/alpha", "/legacy")

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        # Return good API response only for non-deprecated paths
        if "/api" in url and not any(p in url for p in deprecated_patterns):
            return _good_api_resp()
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
