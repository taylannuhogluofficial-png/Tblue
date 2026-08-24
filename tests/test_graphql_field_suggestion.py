"""Tests for GraphQL Field Suggestion & Schema Enumeration via Error Messages scanner."""

import json
import pytest
from unittest.mock import MagicMock, patch

from tblue.scanner.graphql_field_suggestion import GraphQLFieldSuggestionScanner


def _make_scanner():
    session = MagicMock()
    return GraphQLFieldSuggestionScanner(session)


def _resp(text="", status_code=200, headers=None):
    r = MagicMock()
    r.text = text
    r.status_code = status_code
    r.headers = headers or {}
    return r


def _gql_error(message, extensions=None):
    payload = {"errors": [{"message": message}]}
    if extensions:
        payload["errors"][0]["extensions"] = extensions
    return _resp(json.dumps(payload))


def _gql_data(data):
    return _resp(json.dumps({"data": data}))


def _404():
    return _resp("Not Found", status_code=404)


# 1 — Unreachable target
def test_unreachable_target():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert len(results) == 1
    assert results[0]["status"] == "PASS"


# 2 — No GraphQL endpoint found → PASS
def test_no_graphql_endpoint():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    assert all(r["status"] == "PASS" for r in results)


# 3 — Field suggestion enabled → FAIL
def test_field_suggestion_enabled_fail():
    s = _make_scanner()
    error_body = json.dumps({
        "errors": [{
            "message": "Cannot query field 'nonExistentFieldXyz' on type 'Query'. "
                       "Did you mean 'users'?",
            "locations": [{"line": 1, "column": 3}]
        }]
    })

    def fake_get(url, **kw):
        return _resp("<html></html>")

    call_count = [0]

    def fake_post(url, **kw):
        call_count[0] += 1
        if "/graphql" in url:
            if call_count[0] == 1:
                # __typename probe — valid response
                return _gql_data({"__typename": "Query"})
            else:
                # field suggestion probe
                return _resp(error_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    fail_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_findings) >= 1
    assert "suggestion" in fail_findings[0]["type"].lower() or "enumerable" in fail_findings[0]["type"].lower()
    assert "users" in fail_findings[0]["detail"] or "did you mean" in fail_findings[0]["detail"].lower()


# 4 — Type name in error message → WARN
def test_type_name_in_error_warn():
    s = _make_scanner()
    error_body = json.dumps({
        "errors": [{
            "message": "Cannot query field 'badField' on type 'UserAccount'.",
            "locations": [{"line": 1, "column": 3}]
        }]
    })

    call_count = [0]

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        call_count[0] += 1
        if "/graphql" in url:
            if call_count[0] == 1:
                return _gql_data({"__typename": "Query"})
            return _resp(error_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    warn_findings = [r for r in results if r["status"] == "WARN"]
    assert len(warn_findings) >= 1
    assert "UserAccount" in warn_findings[0]["detail"]


# 5 — Stack trace in error response → FAIL
def test_stack_trace_in_error_fail():
    s = _make_scanner()
    error_body = json.dumps({
        "errors": [{
            "message": "Unexpected error.",
            "extensions": {
                "code": "INTERNAL_SERVER_ERROR",
                "exception": {
                    "stacktrace": [
                        "Error: something went wrong",
                        "    at /app/src/resolvers/user.js:45:23"
                    ]
                }
            }
        }]
    })

    call_count = [0]

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        call_count[0] += 1
        if "/graphql" in url:
            if call_count[0] == 1:
                return _gql_data({"__typename": "Query"})
            return _resp(error_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    fail_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_findings) >= 1
    assert "stack" in fail_findings[0]["type"].lower() or "trace" in fail_findings[0]["type"].lower()


# 6 — File path in error message → FAIL
def test_filepath_in_error_fail():
    s = _make_scanner()
    error_body = json.dumps({
        "errors": [{
            "message": "Internal error at /srv/app/resolvers/users.ts:123:7"
        }]
    })

    call_count = [0]

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        call_count[0] += 1
        if "/graphql" in url:
            if call_count[0] == 1:
                return _gql_data({"__typename": "Query"})
            return _resp(error_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    fail_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_findings) >= 1


# 7 — Generic GraphQL error (no suggestion, no type name) → PASS
def test_generic_error_no_schema_leak_pass():
    s = _make_scanner()
    error_body = json.dumps({
        "errors": [{
            "message": "An unknown error occurred."
        }]
    })

    call_count = [0]

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        call_count[0] += 1
        if "/graphql" in url:
            if call_count[0] == 1:
                return _gql_data({"__typename": "Query"})
            return _resp(error_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    # No schema leak found → PASS
    assert any(r["status"] == "PASS" for r in results)
    fail_warn = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert len(fail_warn) == 0


# 8 — Endpoint responds with non-GraphQL body → skip
def test_non_graphql_response_skipped():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        if "/graphql" in url:
            return _resp("<html>Welcome to my site</html>")
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    assert all(r["status"] == "PASS" for r in results)


# 9 — Endpoint found at /api/graphql (not just /graphql)
def test_api_graphql_path_checked():
    s = _make_scanner()
    error_body = json.dumps({
        "errors": [{
            "message": "Cannot query field 'x' on type 'Root'. Did you mean 'query'?"
        }]
    })

    call_count = [0]

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        call_count[0] += 1
        if "/api/graphql" in url:
            if call_count[0] == 1:
                return _gql_data({"__typename": "Query"})
            return _resp(error_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    fail_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_findings) >= 1
    assert "/api/graphql" in fail_findings[0]["url"]


# 10 — POST raises exception → handled gracefully
def test_exception_in_post_handled():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        raise ConnectionError("timeout")

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    assert any(r["status"] == "PASS" for r in results)


# 11 — 400 status with errors body → still treated as GraphQL endpoint
def test_400_with_errors_body_is_graphql():
    s = _make_scanner()
    # GraphQL servers often return 400 for validation errors
    typename_resp = _resp(
        json.dumps({"errors": [{"message": "validation error"}]}),
        status_code=400
    )
    error_body = json.dumps({
        "errors": [{
            "message": "Cannot query field 'xyz' on type 'Query'. Did you mean 'node'?"
        }]
    })

    call_count = [0]

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        call_count[0] += 1
        if "/graphql" in url:
            if call_count[0] == 1:
                return typename_resp
            return _resp(error_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    fail_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_findings) >= 1


# 13 — __typename response confirms endpoint (line 164 coverage)
def test_typename_disclosure_logged():
    s = _make_scanner()
    # __typename probe succeeds with exact typename pattern → logs warning
    typename_resp = _gql_data({"__typename": "Query"})
    error_body = json.dumps({"errors": [{"message": "Generic error."}]})

    call_count = [0]

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        call_count[0] += 1
        if "/graphql" in url:
            if call_count[0] == 1:
                return typename_resp
            return _resp(error_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    # Should pass (no schema leak) but endpoint was found
    assert any(r["status"] == "PASS" for r in results)


# 14 — Second POST raises exception → handled (line 240-241)
def test_second_post_exception_handled():
    s = _make_scanner()
    call_count = [0]

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        call_count[0] += 1
        if "/graphql" in url:
            if call_count[0] == 1:
                return _gql_data({"__typename": "Query"})
            raise RuntimeError("connection reset")
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    # Exception in step 2 should be caught
    assert any(r["status"] == "PASS" for r in results)


# 15 — Second POST returns empty body → returns found (line 177-178)
def test_second_post_empty_body_returns():
    s = _make_scanner()
    call_count = [0]

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        call_count[0] += 1
        if "/graphql" in url:
            if call_count[0] == 1:
                return _gql_data({"__typename": "Query"})
            return _resp("")  # Empty body
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    assert any(r["status"] == "PASS" for r in results)


# 12 — Second POST returns None → no crash
def test_second_post_none_no_crash():
    s = _make_scanner()
    call_count = [0]

    def fake_get(url, **kw):
        return _resp("<html></html>")

    def fake_post(url, **kw):
        call_count[0] += 1
        if "/graphql" in url:
            if call_count[0] == 1:
                return _gql_data({"__typename": "Query"})
            return None  # Second probe returns None
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        with patch.object(s.http, "post", side_effect=fake_post):
            results = s.scan("https://example.com")

    assert any(r["status"] == "PASS" for r in results)
