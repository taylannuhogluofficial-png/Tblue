"""Tests for GraphQL Authorization scanner."""
import unittest
from unittest.mock import MagicMock, patch
import json
from tblue.scanner.graphql_authorization import GraphQLAuthorizationScanner


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestGraphQLAuthorization(unittest.TestCase):

    def _scanner(self):
        s = GraphQLAuthorizationScanner.__new__(GraphQLAuthorizationScanner)
        s.http = MagicMock()
        s.results = []
        s._result = lambda url, ftype, sev, detail="": {
            "url": url, "type": ftype, "severity": sev, "detail": detail
        }
        return s

    def _not_found(self):
        return _resp("", 404)

    def test_no_graphql_endpoint(self):
        s = self._scanner()
        s.http.get.return_value = self._not_found()
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("graphql_auth_no_endpoint", types)

    def test_introspection_without_auth(self):
        s = self._scanner()
        schema = {"data": {"__schema": {"types": [
            {"name": "Query", "kind": "OBJECT", "fields": [{"name": "users"}]},
            {"name": "Mutation", "kind": "OBJECT", "fields": [{"name": "deleteUser"}]},
        ]}}}

        def get_side(url, **kw):
            if "/graphql" in url and "__schema" in url:
                return _resp(json.dumps(schema), 200)
            if "/graphql" in url:
                return _resp('{"data":{}}', 200)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("graphql_introspection_no_auth", types)

    def test_sensitive_mutation_detected(self):
        s = self._scanner()
        schema = {"data": {"__schema": {"types": [
            {"name": "Mutation", "kind": "OBJECT", "fields": [
                {"name": "deleteUser", "args": [{"name": "id"}]},
                {"name": "setAdmin", "args": [{"name": "userId"}]},
            ]},
        ]}}}

        def get_side(url, **kw):
            if "__schema" in url:
                return _resp(json.dumps(schema), 200)
            if "/graphql" in url:
                return _resp('{}', 200)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("graphql_sensitive_mutations_exposed", types)

    def test_cors_wildcard_on_graphql(self):
        s = self._scanner()

        def get_side(url, **kw):
            if "/graphql" in url:
                return _resp('{"data":{}}', 200,
                             headers={"access-control-allow-origin": "*"})
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("graphql_cors_wildcard", types)

    def test_auth_error_response_no_flag(self):
        s = self._scanner()
        auth_err = {"errors": [{"message": "Unauthorized: must be logged in"}]}

        def get_side(url, **kw):
            if "/graphql" in url:
                return _resp(json.dumps(auth_err), 200)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        # Should not flag introspection as no-auth since auth error present
        self.assertNotIn("graphql_introspection_no_auth", types)


if __name__ == "__main__":
    unittest.main()
