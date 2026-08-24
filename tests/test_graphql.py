"""
Tests for GraphQL security scanner.
"""

import pytest
import json
from unittest.mock import MagicMock
from tblue.scanner.graphql import GraphQLScanner


def make_scanner(path_map: dict = None) -> GraphQLScanner:
    """
    path_map: {url_suffix: (status_code, body, content_type)}
    Unmatched paths return 404.
    """
    path_map = path_map or {}
    session  = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        for suffix, (code, body, ct) in path_map.items():
            if url.endswith(suffix) or suffix in url:
                resp.status_code = code
                resp.text        = body
                resp.headers     = {"content-type": ct}
                resp.url         = url
                return resp
        resp.status_code = 404
        resp.text        = "Not Found"
        resp.headers     = {}
        resp.url         = url
        return resp

    session.request.side_effect = fake_request
    return GraphQLScanner(session)


_INTROSPECTION_RESPONSE = json.dumps({
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "types": [{"name": "User"}, {"name": "String"}]
        }
    }
})

_BATCH_RESPONSE = json.dumps([
    {"data": {"__typename": "Query"}},
    {"data": {"__typename": "Query"}},
])

_PLAYGROUND_HTML = "<html><head><title>GraphiQL</title></head><body><div id='graphiql'>Loading...</div></body></html>"


# ── Introspection tests ───────────────────────────────────────────────────────

def test_introspection_enabled_fails():
    scanner = make_scanner({"/graphql": (200, _INTROSPECTION_RESPONSE, "application/json")})
    results = scanner.scan("https://example.com")
    assert any("introspection enabled" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_introspection_disabled_no_fail():
    scanner = make_scanner({"/graphql": (200, '{"errors":[{"message":"introspection disabled"}]}', "application/json")})
    results = scanner.scan("https://example.com")
    assert not any("introspection enabled" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_no_graphql_endpoint_passes():
    scanner = make_scanner()  # all 404
    results = scanner.scan("https://example.com")
    assert any("no endpoint detected" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ── Playground tests ──────────────────────────────────────────────────────────

def test_playground_exposed_warns():
    scanner = make_scanner({"/graphiql": (200, _PLAYGROUND_HTML, "text/html")})
    results = scanner.scan("https://example.com")
    assert any("playground" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Batch query tests ─────────────────────────────────────────────────────────

def test_batching_enabled_warns():
    """When introspection passes AND batch query returns a list, batching is flagged WARN."""
    post_count = [0]
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.url = url
        if "/graphql" not in url:
            resp.status_code = 404
            resp.text = "Not Found"
            resp.headers = {}
            return resp
        if method == "GET":
            resp.status_code = 404   # no playground
            resp.text = "Not Found"
            resp.headers = {}
            return resp
        # POST: first is introspection probe, second is batch probe
        post_count[0] += 1
        resp.status_code = 200
        resp.headers = {"content-type": "application/json"}
        resp.text = _INTROSPECTION_RESPONSE if post_count[0] == 1 else _BATCH_RESPONSE
        return resp

    session.request.side_effect = fake_request
    s = GraphQLScanner(session)
    results = s.scan("https://example.com")
    assert any("introspection" in r["type"].lower() and r["status"] == "FAIL" for r in results)
    assert any("batching" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_result_has_fix_guidance():
    scanner = make_scanner({"/graphql": (200, _INTROSPECTION_RESPONSE, "application/json")})
    results = scanner.scan("https://example.com")
    fails   = [r for r in results if r["status"] == "FAIL"]
    assert any(len(r.get("detail", "")) > 20 for r in fails)


def test_batch_post_exception_does_not_crash():
    # Introspection enabled; second POST (batch probe) raises an exception
    # The scanner wraps it in try/except — should not propagate
    from tblue.scanner.graphql import GraphQLScanner
    from unittest.mock import MagicMock
    post_count = [0]
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.url = url
        if "/graphql" not in url:
            resp.status_code = 404
            resp.text = "Not Found"
            resp.headers = {}
            return resp
        if method == "GET":
            resp.status_code = 404
            resp.text = "Not Found"
            resp.headers = {}
            return resp
        post_count[0] += 1
        if post_count[0] == 1:
            resp.status_code = 200
            resp.headers = {"content-type": "application/json"}
            resp.text = _INTROSPECTION_RESPONSE
            return resp
        raise Exception("timeout on batch probe")

    session.request.side_effect = fake_request
    s = GraphQLScanner(session)
    results = s.scan("https://example.com")
    assert any("introspection" in r["type"].lower() and r["status"] == "FAIL" for r in results)
