"""Tests for GraphQLIntrospectionSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.graphql_introspection_security import GraphQLIntrospectionSecurityScanner


def _scanner():
    s = GraphQLIntrospectionSecurityScanner.__new__(GraphQLIntrospectionSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_introspection_enabled():
    s = _scanner()
    s.http.get.return_value = _resp(
        '{"data": {"__schema": {"types": [{"name": "Query"}, {"name": "User"}]}}}'
    )
    results = s.scan("http://example.com/graphql")
    types = [r["type"] for r in results]
    assert "graphql_introspection_enabled" in types


def test_graphql_stack_trace():
    s = _scanner()
    s.http.get.return_value = _resp(
        '{"errors": [{"message": "Error", "extensions": {"stacktrace": ["at resolver.js:42"]}}]}'
    )
    results = s.scan("http://example.com/graphql")
    types = [r["type"] for r in results]
    assert "graphql_stack_trace_in_extensions" in types


def test_graphql_playground():
    s = _scanner()
    s.http.get.return_value = _resp(
        '<html><title>GraphQL Playground</title><body>GraphiQL interface</body></html>'
    )
    results = s.scan("http://example.com/graphql")
    types = [r["type"] for r in results]
    assert "graphql_ide_enabled" in types


def test_graphql_field_suggestion():
    s = _scanner()
    s.http.get.return_value = _resp(
        '{"errors": [{"message": "Cannot query field \'usesr\' on type \'Query\'. Did you mean \'users\'?"}]}'
    )
    results = s.scan("http://example.com/graphql")
    types = [r["type"] for r in results]
    assert "graphql_field_suggestion_disclosure" in types


def test_graphql_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Regular HTML page</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "graphql_introspection_not_used"
    assert results[0]["status"] == "PASS"
