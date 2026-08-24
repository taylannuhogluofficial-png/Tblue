"""Tests for tblue.scanner.graphql_depth — GraphQL depth limiting scanner."""

import json
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.graphql_depth import GraphQLDepthScanner, _build_alias_query


def _scanner():
    session = MagicMock()
    return GraphQLDepthScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {"content-type": "application/json"}
    return r


def _gql_resp(data=None, errors=None):
    payload = {}
    if data is not None:
        payload["data"] = data
    if errors is not None:
        payload["errors"] = errors
    return _resp(200, json.dumps(payload))


# ── No response → PASS ────────────────────────────────────────────────────────

def test_no_response_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


# ── No GraphQL endpoint → PASS ────────────────────────────────────────────────

def test_no_graphql_endpoint_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        with patch.object(s.http, "post", return_value=_resp(404, "Not Found")):
            results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


# ── GraphQL found, deep query accepted → FAIL ─────────────────────────────────

def test_deep_query_accepted_fails():
    s = _scanner()
    gql_discovery_resp = _gql_resp(data={"__typename": "Query"})
    gql_deep_resp = _gql_resp(data={"__schema": {"types": []}})

    call_count = [0]
    def post_side_effect(url, **kwargs):
        call_count[0] += 1
        return gql_deep_resp if call_count[0] > 1 else gql_discovery_resp

    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        with patch.object(s.http, "post", side_effect=post_side_effect):
            results = s.scan("https://example.com")

    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("depth" in r["type"].lower() or "deep" in r["type"].lower() for r in fails)


# ── GraphQL found, depth error returned → PASS ────────────────────────────────

def test_depth_error_returned_passes():
    s = _scanner()
    gql_discovery_resp = _gql_resp(data={"__typename": "Query"})
    gql_error_resp = _gql_resp(errors=[{"message": "Query exceeds max depth of 5"}])

    call_count = [0]
    def post_side_effect(url, **kwargs):
        call_count[0] += 1
        return gql_error_resp if call_count[0] > 1 else gql_discovery_resp

    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        with patch.object(s.http, "post", side_effect=post_side_effect):
            results = s.scan("https://example.com")

    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
    assert any("enforced" in r["type"].lower() or "depth" in r["type"].lower() for r in passes)


# ── Alias amplification accepted → WARN ─────────────────────────────────────

def test_alias_amplification_warns():
    s = _scanner()
    aliases_data = {f"f{i}": "Query" for i in range(100)}
    gql_discovery_resp = _gql_resp(data={"__typename": "Query"})
    gql_deep_resp = _gql_resp(data={"f0": "x"})  # No depth limit, but no f99
    gql_alias_resp = _gql_resp(data=aliases_data)  # Has f99

    call_count = [0]
    def post_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return gql_discovery_resp
        if call_count[0] == 2:
            return gql_deep_resp
        return gql_alias_resp

    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        with patch.object(s.http, "post", side_effect=post_side_effect):
            results = s.scan("https://example.com")

    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("alias" in r["type"].lower() or "amplif" in r["type"].lower() for r in warns)


# ── _build_alias_query ────────────────────────────────────────────────────────

def test_build_alias_query_has_correct_count():
    q = _build_alias_query(5)
    assert "f0:" in q
    assert "f4:" in q
    assert "f5:" not in q


def test_build_alias_query_valid_graphql_structure():
    q = _build_alias_query(3)
    assert q.startswith("{ ")
    assert q.endswith(" }")
    assert "__typename" in q


# ── Discovery: endpoint on /api/graphql ──────────────────────────────────────

def test_discovers_api_graphql_path():
    s = _scanner()
    gql_resp = _gql_resp(data={"__typename": "Query"})

    def post_side_effect(url, **kwargs):
        if "/api/graphql" in url:
            return gql_resp
        return _resp(404, "not found")

    deep_resp = _gql_resp(data={"__schema": {}})
    call_count_after_discovery = [0]
    def post_side_effect_full(url, **kwargs):
        if "/api/graphql" in url and call_count_after_discovery[0] == 0:
            call_count_after_discovery[0] += 1
            return gql_resp
        return deep_resp

    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        with patch.object(s.http, "post", side_effect=post_side_effect_full):
            result = s._find_graphql_endpoint("https://example.com")
    assert result is not None
    assert "graphql" in result.lower()


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_build_deep_query_covers_function():
    """Call _build_deep_query to cover lines 48-52."""
    from tblue.scanner.graphql_depth import _build_deep_query
    q = _build_deep_query(3)
    assert "__typename" in q
    assert q.startswith("{")
    assert "}" in q


def test_no_issues_detected_fallback_pass():
    """Endpoint found but deep/alias responses don't match RE → lines 186-187 fire."""
    s = _scanner()
    gql_discovery_resp = _gql_resp(data={"__typename": "Query"})
    empty_resp = _resp(200, "OK")

    call_count = [0]
    def post_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return gql_discovery_resp
        return empty_resp

    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        with patch.object(s.http, "post", side_effect=post_side_effect):
            results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_find_endpoint_post_returns_none_continues():
    """post returns None for all probe paths → if r is None: continue at line 202."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        with patch.object(s.http, "post", return_value=None):
            results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)
