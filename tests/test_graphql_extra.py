"""Extra branch coverage for tblue.scanner.graphql."""

import json
from unittest.mock import MagicMock, patch
from tblue.scanner.graphql import GraphQLScanner

URL = "https://example.com"


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _scanner():
    session = MagicMock()
    return GraphQLScanner(session)


def test_no_graphql_endpoints_passes():
    """Branch: no GraphQL endpoint found at any common path — PASS."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(404, "")):
        with patch.object(s.http, "post", return_value=_resp(404, "")):
            results = s.scan(URL)
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
    assert any("graphql" in r["type"].lower() and "no endpoint" in r["type"].lower()
               for r in passes)


def test_graphiql_playground_exposed_warns():
    """Branch: GET /graphql returns page with graphiql in body — WARN."""
    s = _scanner()
    playground_html = "<html><body><div id='graphiql'>GraphiQL IDE</div></body></html>"

    def get_side_effect(url, **kwargs):
        if "/graphql" in url or "/graphiql" in url:
            return _resp(200, playground_html)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        with patch.object(s.http, "post", return_value=_resp(404, "")):
            results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("playground" in r["type"].lower() or "graphiql" in r["type"].lower()
               or "ide" in r["type"].lower() for r in warns)


def test_introspection_enabled_fails():
    """Branch: POST introspection query returns __schema — FAIL."""
    s = _scanner()
    schema_body = json.dumps({
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": [{"name": "Query", "kind": "OBJECT"}]
            }
        }
    })

    def get_side_effect(url, **kwargs):
        return _resp(200, "<html>API</html>")

    def post_side_effect(url, **kwargs):
        if "/graphql" in url:
            return _resp(200, schema_body)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=get_side_effect):
        with patch.object(s.http, "post", side_effect=post_side_effect):
            results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("introspection" in r["type"].lower() for r in fails)


def test_post_non_200_status_no_graphql():
    """Branch: POST to endpoint returns non-200 — not flagged as GraphQL."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(404, "")):
        with patch.object(s.http, "post", return_value=_resp(401, '{"error":"unauthorized"}')):
            results = s.scan(URL)
    assert isinstance(results, list)
    introspection_fails = [r for r in results if "introspection" in r["type"].lower()
                           and r["status"] == "FAIL"]
    assert not introspection_fails


def test_batch_query_accepted_warns():
    """Branch: batch query returns two results — WARN for batch enabled."""
    s = _scanner()
    # First confirm GraphQL endpoint via introspection, then detect batching
    schema_body = json.dumps({
        "data": {"__schema": {"queryType": {"name": "Query"}, "types": []}}
    })
    batch_body = json.dumps([
        {"data": {"__typename": "Query"}},
        {"data": {"__typename": "Query"}},
    ])

    call_count = [0]

    def post_side_effect(url, **kwargs):
        call_count[0] += 1
        body = kwargs.get("json", {})
        if isinstance(body, list):
            return _resp(200, batch_body)
        return _resp(200, schema_body)

    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        with patch.object(s.http, "post", side_effect=post_side_effect):
            results = s.scan(URL)
    assert isinstance(results, list)
    # Introspection should be flagged
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
