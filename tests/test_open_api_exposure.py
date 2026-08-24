"""Tests for tblue.scanner.open_api_exposure — OpenAPI/Swagger exposure scanner."""

import json
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.open_api_exposure import OpenAPIExposureScanner


def _scanner():
    session = MagicMock()
    return OpenAPIExposureScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


# ── None response → PASS ──────────────────────────────────────────────────────

def test_no_response_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


# ── No spec endpoints found → PASS ───────────────────────────────────────────

def test_no_spec_endpoints_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(404, "Not Found")):
        results = s.scan("https://example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
    assert any("no documentation" in r["type"].lower() for r in passes)


# ── Swagger UI exposed → WARN ─────────────────────────────────────────────────

def test_swagger_ui_exposed_warns():
    s = _scanner()
    swagger_body = '<html><div id="swagger-ui">...</div></html>'

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        if "swagger" in url.lower() or "api-docs" in url.lower():
            return _resp(200, swagger_body, {"content-type": "text/html"})
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("swagger" in r["type"].lower() or "documentation" in r["type"].lower()
               for r in warns)


# ── Redoc UI exposed → WARN ───────────────────────────────────────────────────

def test_redoc_ui_exposed_warns():
    s = _scanner()
    redoc_body = '<html><redoc spec-url="/openapi.json"></redoc></html>'

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        if "/redoc" in url or "/docs" in url:
            return _resp(200, redoc_body, {"content-type": "text/html"})
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("redoc" in r["type"].lower() or "documentation" in r["type"].lower()
               for r in warns)


# ── Machine-readable OpenAPI spec exposed → WARN ──────────────────────────────

def test_openapi_spec_exposed_warns():
    s = _scanner()
    spec_body = json.dumps({
        "openapi": "3.0.0",
        "info": {"title": "My API", "version": "1.0"},
        "paths": {"/users": {"get": {"summary": "List users"}}},
    })

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        if "/openapi.json" in url or "/api-docs" in url:
            return _resp(200, spec_body, {"content-type": "application/json"})
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("spec" in r["type"].lower() or "openapi" in r["type"].lower() for r in warns)


# ── Internal server URL in spec → WARN ───────────────────────────────────────

def test_internal_server_url_warns():
    s = _scanner()
    spec_body = json.dumps({
        "openapi": "3.0.0",
        "info": {"title": "API", "version": "1.0"},
        "servers": [{"url": "https://staging.internal.example.com/api"}],
        "paths": {},
    })

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        if "/openapi.json" in url:
            return _resp(200, spec_body, {"content-type": "application/json"})
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("internal" in r["type"].lower() or "staging" in r["type"].lower()
               for r in warns)


# ── Hardcoded secret in spec example → FAIL ──────────────────────────────────

def test_hardcoded_secret_in_spec_fails():
    s = _scanner()
    spec_body = json.dumps({
        "openapi": "3.0.0",
        "info": {"title": "API", "version": "1.0"},
        "paths": {},
        "components": {
            "examples": {
                "auth": {"value": {"api_key": "sk_live_AbCdEf1234567890XyZqRs"}}
            }
        }
    })

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        if "/openapi.json" in url:
            return _resp(200, spec_body, {"content-type": "application/json"})
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("secret" in r["type"].lower() or "api key" in r["type"].lower() for r in fails)


# ── Protected endpoint (401) → PASS ──────────────────────────────────────────

def test_protected_spec_passes():
    s = _scanner()

    def get_side_effect(url, **kwargs):
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        # All spec paths return 401
        return _resp(401, "Unauthorized")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
