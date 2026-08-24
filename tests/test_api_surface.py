"""Tests for tblue.scanner.api_surface — APISurfaceScanner."""

import json
import pytest
from unittest.mock import MagicMock, patch

from tblue.scanner.api_surface import (
    APISurfaceScanner,
    _parse_spec,
    _find_sensitive_schema_fields,
    _base_url,
)

URL = "https://example.com"


def _make_scanner():
    session = MagicMock()
    return APISurfaceScanner(session)


def _mock_resp(status=200, body="", content_type="application/json"):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {"content-type": content_type}
    return r


# ── _base_url ────────────────────────────────────────────────────────────────

def test_base_url():
    assert _base_url("https://example.com/path?q=1") == "https://example.com"


# ── _parse_spec ───────────────────────────────────────────────────────────────

def test_parse_spec_openapi_json():
    body = json.dumps({"openapi": "3.0.0", "paths": {"/users": {}}})
    result = _parse_spec(body)
    assert result is not None
    assert result["openapi"] == "3.0.0"


def test_parse_spec_swagger_json():
    body = json.dumps({"swagger": "2.0", "paths": {}})
    assert _parse_spec(body) is not None


def test_parse_spec_invalid_json():
    assert _parse_spec("not json at all") is None


def test_parse_spec_json_no_paths():
    # JSON but not a spec (no paths/openapi/swagger key)
    assert _parse_spec(json.dumps({"foo": "bar"})) is None


def test_parse_spec_yaml_openapi(monkeypatch):
    yaml_body = "openapi: 3.0.0\npaths:\n  /users:\n    get: {}\n"
    import importlib
    import sys

    # Simulate yaml being available
    class FakeYaml:
        @staticmethod
        def safe_load(s):
            return {"openapi": "3.0.0", "paths": {"/users": {"get": {}}}}

    monkeypatch.setitem(sys.modules, "yaml", FakeYaml)
    result = _parse_spec(yaml_body)
    assert result is not None


def test_parse_spec_yaml_exception(monkeypatch):
    import sys

    class BadYaml:
        @staticmethod
        def safe_load(s):
            raise ValueError("bad yaml")

    monkeypatch.setitem(sys.modules, "yaml", BadYaml)
    body = "openapi: 3.0.0\npaths:\n"
    # Should return None gracefully
    result = _parse_spec(body)
    assert result is None


# ── _find_sensitive_schema_fields ─────────────────────────────────────────────

def test_find_sensitive_fields_password():
    spec = {
        "components": {
            "schemas": {
                "User": {
                    "properties": {
                        "username": {"type": "string"},
                        "password": {"type": "string"},
                    }
                }
            }
        }
    }
    fields = _find_sensitive_schema_fields(spec)
    assert "password" in fields


def test_find_sensitive_fields_apikey():
    spec = {
        "components": {
            "schemas": {
                "Auth": {"properties": {"api_key": {"type": "string"}}}
            }
        }
    }
    assert "api_key" in _find_sensitive_schema_fields(spec)


def test_find_sensitive_fields_none():
    spec = {
        "components": {
            "schemas": {
                "User": {"properties": {"username": {"type": "string"}}}
            }
        }
    }
    assert _find_sensitive_schema_fields(spec) == []


def test_find_sensitive_fields_definitions_fallback():
    # Swagger 2.0 uses definitions instead of components/schemas
    spec = {
        "definitions": {
            "Token": {"properties": {"access_key": {"type": "string"}}}
        }
    }
    fields = _find_sensitive_schema_fields(spec)
    assert "access_key" in fields


def test_find_sensitive_fields_non_dict_schema():
    spec = {
        "components": {
            "schemas": {"BadSchema": "not a dict"}
        }
    }
    # Should not crash
    assert _find_sensitive_schema_fields(spec) == []


# ── scan() — no docs found ────────────────────────────────────────────────────

def test_scan_no_docs_found():
    scanner = _make_scanner()
    with patch.object(scanner.http, "get", return_value=None):
        results = scanner.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_scan_all_404():
    scanner = _make_scanner()
    resp_404 = _mock_resp(status=404, body="not found")
    with patch.object(scanner.http, "get", return_value=resp_404):
        results = scanner.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


# ── scan() — Swagger UI HTML ──────────────────────────────────────────────────

def test_scan_swagger_ui_exposed():
    scanner = _make_scanner()
    swagger_html = "<html><body>Swagger UI</body></html>"
    ui_resp = _mock_resp(status=200, body=swagger_html, content_type="text/html")
    not_found = _mock_resp(status=404)

    def side_effect(url, **kwargs):
        if "swagger-ui" in url or "swagger.json" not in url:
            return ui_resp
        return not_found

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    assert any("Swagger UI" in r["type"] for r in results)
    assert any(r["status"] == "WARN" for r in results)


# ── scan() — OpenAPI spec parsed ──────────────────────────────────────────────

def _openapi_spec(routes=None, global_sec=None, sensitive_props=None):
    paths = routes or {"/users": {"get": {}, "post": {}}}
    spec = {"openapi": "3.0.0", "info": {"title": "Test API", "version": "1.0"}, "paths": paths}
    if global_sec is not None:
        spec["security"] = global_sec
    if sensitive_props:
        spec["components"] = {
            "schemas": {
                "User": {"properties": {p: {"type": "string"} for p in sensitive_props}}
            }
        }
    return spec


def test_scan_openapi_spec_exposed():
    scanner = _make_scanner()
    spec_body = json.dumps(_openapi_spec())
    spec_resp = _mock_resp(status=200, body=spec_body)
    not_found = _mock_resp(status=404)

    def side_effect(url, **kwargs):
        if url.endswith("/openapi.json"):
            return spec_resp
        return not_found

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    assert any("OpenAPI specification exposed" in r["type"] for r in results)
    assert any(r["status"] == "FAIL" for r in results)


def test_scan_openapi_unprotected_routes():
    scanner = _make_scanner()
    # Routes with security: [] (explicit empty = no auth required)
    paths = {"/admin": {"delete": {"security": []}}}
    spec_body = json.dumps(_openapi_spec(routes=paths))
    spec_resp = _mock_resp(status=200, body=spec_body)
    not_found = _mock_resp(status=404)

    def side_effect(url, **kwargs):
        if url.endswith("/openapi.json"):
            return spec_resp
        return not_found

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    types = [r["type"] for r in results]
    assert any("routes without security" in t for t in types)


def test_scan_openapi_sensitive_fields():
    scanner = _make_scanner()
    spec_body = json.dumps(_openapi_spec(sensitive_props=["password", "api_key"]))
    spec_resp = _mock_resp(status=200, body=spec_body)
    not_found = _mock_resp(status=404)

    def side_effect(url, **kwargs):
        if url.endswith("/openapi.json"):
            return spec_resp
        return not_found

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    assert any("sensitive field names" in r["type"] for r in results)


def test_scan_unparseable_doc():
    scanner = _make_scanner()
    # 200 but not JSON and not YAML spec
    resp = _mock_resp(status=200, body="just some random text", content_type="text/plain")
    not_found = _mock_resp(status=404)

    def side_effect(url, **kwargs):
        if url.endswith("/openapi.json"):
            return resp
        return not_found

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    assert any("unparseable" in r["type"] for r in results)


def test_scan_exception_in_probe():
    """Exception in a single probe should not stop the scan."""
    scanner = _make_scanner()
    call_count = {"n": 0}

    def side_effect(url, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise ConnectionError("timeout")
        return _mock_resp(status=404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_scan_non_dict_path_value():
    """Path value that is not a dict should be skipped (line 130: continue)."""
    scanner = _make_scanner()
    paths = {"/items": "not-a-dict"}   # non-dict value → skip
    spec_body = json.dumps(_openapi_spec(routes=paths))
    spec_resp = _mock_resp(status=200, body=spec_body)
    not_found = _mock_resp(status=404)

    def side_effect(url, **kwargs):
        if url.endswith("/openapi.json"):
            return spec_resp
        return not_found

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    # Spec is found, 0 routes, no unprotected routes
    assert any("OpenAPI specification exposed" in r["type"] for r in results)
    assert not any("routes without security" in r["type"] for r in results)


def test_scan_all_routes_protected():
    """All routes have security scheme → no unprotected-routes finding (covers 138→131)."""
    scanner = _make_scanner()
    paths = {"/admin": {"get": {"security": [{"bearer": []}]}}}
    spec_body = json.dumps(_openapi_spec(routes=paths))
    spec_resp = _mock_resp(status=200, body=spec_body)
    not_found = _mock_resp(status=404)

    def side_effect(url, **kwargs):
        if url.endswith("/openapi.json"):
            return spec_resp
        return not_found

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    assert any("OpenAPI specification exposed" in r["type"] for r in results)
    assert not any("routes without security" in r["type"] for r in results)


def test_parse_spec_yaml_non_dict_result(monkeypatch):
    """YAML parses to non-dict → returns None (covers 197→201)."""
    import sys

    class FakeYaml:
        @staticmethod
        def safe_load(s):
            return ["a", "list"]  # not a dict

    monkeypatch.setitem(sys.modules, "yaml", FakeYaml)
    body = "openapi: 3.0.0\npaths:\n  /users: {}\n"
    result = _parse_spec(body)
    assert result is None


def test_scan_x_extension_methods_skipped():
    """x-* methods in paths should not be counted as routes."""
    scanner = _make_scanner()
    paths = {"/items": {"get": {}, "x-custom": "extension"}}
    spec_body = json.dumps(_openapi_spec(routes=paths))
    spec_resp = _mock_resp(status=200, body=spec_body)
    not_found = _mock_resp(status=404)

    def side_effect(url, **kwargs):
        if url.endswith("/openapi.json"):
            return spec_resp
        return not_found

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    # Should expose spec (get route counted) but not crash on x- key
    assert any("OpenAPI specification exposed" in r["type"] for r in results)
