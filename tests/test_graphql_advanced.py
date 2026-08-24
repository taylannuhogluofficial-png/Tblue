"""Tests for tblue.scanner.graphql_advanced — Advanced GraphQL scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.graphql_advanced import GraphQLAdvancedScanner


def _scanner():
    session = MagicMock()
    return GraphQLAdvancedScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {"content-type": "application/json"}
    return r


def _404():
    return _resp(status=404, body="")


_INTROSPECTION_RESPONSE = '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[]}}}'
_SENSITIVE_SCHEMA = '{"data":{"__schema":{"types":[{"name":"User","fields":[{"name":"password"},{"name":"token"}]}]}}}'
_STACK_TRACE_RESPONSE = '{"errors":[{"message":"Error","extensions":{"stacktrace":["at resolve (/app/index.js:10:5)"]}}]}'


def test_no_graphql_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html>Hello</html>")):
        with patch.object(s.http, "post", return_value=_404()):
            results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_graphiql_ide_exposed_fail():
    s = _scanner()
    body = '<html><title>GraphiQL</title><script src="graphiql.min.js"></script></html>'
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        with patch.object(s.http, "post", return_value=_404()):
            results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("IDE" in r["type"] or "graphiql" in r["type"].lower() for r in fails)


def test_graphql_playground_fail():
    s = _scanner()
    body = '<html>GraphQL Playground</html>'
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        with patch.object(s.http, "post", return_value=_404()):
            results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_introspection_enabled_warn():
    s = _scanner()
    def get_side_effect(url, **kw):
        return _resp(200, "<html></html>")
    def post_side_effect(url, **kw):
        if "/graphql" in url:
            return _resp(200, _INTROSPECTION_RESPONSE)
        return _404()
    with patch.object(s.http, "get", side_effect=get_side_effect):
        with patch.object(s.http, "post", side_effect=post_side_effect):
            results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("introspection" in r["type"].lower() for r in warns)


def test_sensitive_field_in_schema_warn():
    s = _scanner()
    def get_side_effect(url, **kw):
        return _resp(200, "<html></html>")
    def post_side_effect(url, **kw):
        if "/graphql" in url:
            return _resp(200, _SENSITIVE_SCHEMA)
        return _404()
    with patch.object(s.http, "get", side_effect=get_side_effect):
        with patch.object(s.http, "post", side_effect=post_side_effect):
            results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("sensitive" in r["type"].lower() for r in warns)


def test_stack_trace_in_error_fail():
    s = _scanner()
    def get_side_effect(url, **kw):
        return _resp(200, "<html></html>")
    def post_side_effect(url, **kw):
        if "/graphql" in url:
            return _resp(200, _STACK_TRACE_RESPONSE)
        return _404()
    with patch.object(s.http, "get", side_effect=get_side_effect):
        with patch.object(s.http, "post", side_effect=post_side_effect):
            results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("stack" in r["type"].lower() for r in fails)


def test_no_response():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        with patch.object(s.http, "post", return_value=_404()):
            results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_batching_detected():
    s = _scanner()
    batch_response = '[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]'

    def get_side_effect(url, **kw):
        return _resp(200, "<html></html>")

    def post_side_effect(url, json=None, **kw):
        if not json:
            return _404()
        if isinstance(json, list):
            return _resp(200, batch_response)
        return _resp(200, '{"data":{"__typename":"Query"}}')

    with patch.object(s.http, "get", side_effect=get_side_effect):
        with patch.object(s.http, "post", side_effect=post_side_effect):
            results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("batching" in r["type"].lower() for r in warns)


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_probe_fallback_get_non_200_continues():
    """POST returns 404, fallback GET also returns 404 → continue at line 136."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(404, "")):
        with patch.object(s.http, "post", return_value=_404()):
            results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_probe_endpoint_post_raises_continues():
    """POST raises in endpoint probe loop → except Exception: continue at lines 195-196."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        with patch.object(s.http, "post", side_effect=RuntimeError("connection refused")):
            results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_batching_post_raises_passes():
    """POST raises in batching check → except Exception: pass at lines 220-221."""
    s = _scanner()

    def post_side_effect(url, json=None, **kw):
        if isinstance(json, list):
            raise RuntimeError("timeout")
        return _resp(200, '{"data":{"__typename":"Query"}}')

    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        with patch.object(s.http, "post", side_effect=post_side_effect):
            results = s.scan("https://example.com")
    assert isinstance(results, list)


def test_ide_probe_non_200_continues():
    """GET returns 404 for IDE paths → continue at line 229."""
    s = _scanner()
    _IDE_PATHS = ["/graphiql", "/playground", "/graphql/console"]

    def get_side_effect(url, **kw):
        if any(p in url for p in _IDE_PATHS):
            return _resp(404, "")
        return _resp(200, "<html></html>")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        with patch.object(s.http, "post", return_value=_404()):
            results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_ide_probe_get_raises_continues():
    """GET raises for IDE paths → except Exception: continue at lines 239-240."""
    s = _scanner()
    _IDE_PATHS = ["/graphiql", "/playground", "/graphql/console"]

    def get_side_effect(url, **kw):
        if any(p in url for p in _IDE_PATHS):
            raise RuntimeError("timeout")
        return _resp(200, "<html></html>")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        with patch.object(s.http, "post", return_value=_404()):
            results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)
