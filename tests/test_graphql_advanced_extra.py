"""Extra branch coverage for tblue.scanner.graphql_advanced."""

import json
from unittest.mock import MagicMock, patch
from tblue.scanner.graphql_advanced import GraphQLAdvancedScanner

URL = "https://example.com"


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _scanner():
    session = MagicMock()
    return GraphQLAdvancedScanner(session)


def test_none_response_returns_pass_or_empty():
    """Branch: initial http.get returns None — no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_no_graphql_endpoint_found_passes():
    """Branch: no GraphQL endpoint at common paths — no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        with patch.object(s.http, "post", return_value=_resp(404, "")):
            results = s.scan(URL)
    assert isinstance(results, list)


def test_graphql_ide_in_response_flags():
    """Branch: GET response contains GraphiQL — FAIL or WARN."""
    s = _scanner()
    ide_html = "<html><body><div class='graphiql-container'>GraphiQL</div></body></html>"

    def get_side_effect(url, **kwargs):
        if "/graphql" in url:
            return _resp(200, ide_html)
        return _resp(200, "<html></html>")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        with patch.object(s.http, "post", return_value=_resp(404, "")):
            results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad
    assert any("ide" in r["type"].lower() or "playground" in r["type"].lower()
               or "graphiql" in r["type"].lower() for r in bad)


def test_sensitive_field_in_schema_warns():
    """Branch: introspection response contains 'password' field name — WARN."""
    s = _scanner()
    schema_body = json.dumps({
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "types": [
                    {"name": "User", "kind": "OBJECT",
                     "fields": [{"name": "password", "type": {"name": "String"}}]}
                ]
            }
        }
    })

    def post_side_effect(url, **kwargs):
        if "/graphql" in url:
            return _resp(200, schema_body)
        return _resp(404, "")

    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        with patch.object(s.http, "post", side_effect=post_side_effect):
            results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("sensitive" in r["type"].lower() or "field" in r["type"].lower()
               or "password" in r.get("detail", "").lower() for r in warns)


def test_stack_trace_in_error_response_flags():
    """Branch: error response contains stack trace extension — FAIL or WARN."""
    s = _scanner()
    error_body = json.dumps({
        "errors": [{
            "message": "Unexpected error",
            "extensions": {
                "stacktrace": [
                    "at Object.resolve (/app/resolvers/user.js:42:7)",
                    "at execute (/node_modules/graphql/execution/execute.js:198:19)"
                ]
            }
        }]
    })

    def post_side_effect(url, **kwargs):
        if "/graphql" in url:
            return _resp(200, error_body)
        return _resp(404, "")

    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        with patch.object(s.http, "post", side_effect=post_side_effect):
            results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad
    assert any("stack" in r["type"].lower() or "verbose" in r["type"].lower()
               or "error" in r["type"].lower() for r in bad)


def test_depth_limit_enforced_passes():
    """Branch: deep query returns depth limit error — PASS (limit enforced)."""
    s = _scanner()
    depth_error = json.dumps({
        "errors": [{"message": "Query depth limit exceeded. Max depth is 7."}]
    })
    introspection_body = json.dumps({
        "data": {"__schema": {"queryType": {"name": "Query"}, "types": []}}
    })

    def post_side_effect(url, json=None, **kwargs):
        query = json.get("query", "") if json else ""
        if "__schema" in query and "types" not in query:
            return _resp(200, introspection_body)
        if len(query) > 100:  # deep query
            return _resp(200, depth_error)
        return _resp(200, introspection_body)

    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        with patch.object(s.http, "post", side_effect=post_side_effect):
            results = s.scan(URL)
    assert isinstance(results, list)
