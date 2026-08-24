"""Tests for GraphQL Persisted Queries scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestGraphQLPersistedQueriesScanner:
    def _scanner(self):
        from tblue.scanner.graphql_persisted_queries import GraphQLPersistedQueriesScanner
        return GraphQLPersistedQueriesScanner(MagicMock())

    def _resp(self, body=None, status=200):
        r = MagicMock()
        r.text = body or "{}"
        r.status_code = status
        r.headers = {}
        r.json = MagicMock(return_value=(body if isinstance(body, dict) else {}))
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            with patch.object(s.http, "post", return_value=None):
                results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_graphql_passes(self):
        s = self._scanner()
        resp = self._resp({"errors": [{"message": "Not Found"}]}, 404)
        with patch.object(s.http, "get", return_value=resp):
            with patch.object(s.http, "post", return_value=resp):
                results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_apq_supported_warns(self):
        s = self._scanner()
        apq_resp = self._resp(
            {"errors": [{"message": "PersistedQueryNotFound"}]}, 200
        )
        apq_resp.json = MagicMock(return_value={"errors": [{"message": "PersistedQueryNotFound"}]})
        no_resp = self._resp({}, 404)
        with patch.object(s.http, "get", return_value=no_resp):
            with patch.object(s.http, "post", return_value=apq_resp):
                results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("apq" in r["type"].lower() or "persisted" in r["type"].lower() for r in warns)

    def test_get_execution_warns(self):
        s = self._scanner()
        get_resp = MagicMock()
        get_resp.status_code = 200
        get_resp.headers = {}
        get_resp.json = MagicMock(return_value={"data": {"__typename": "Query"}})
        get_resp.text = '{"data": {"__typename": "Query"}}'
        post_no = self._resp({}, 404)
        with patch.object(s.http, "get", return_value=get_resp):
            with patch.object(s.http, "post", return_value=post_no):
                results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("get" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            with patch.object(s.http, "post", return_value=self._resp()):
                results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_apq_probe_hash_is_correct(self):
        import hashlib
        from tblue.scanner.graphql_persisted_queries import _APQ_PROBE_QUERY, _APQ_PROBE_HASH
        expected = hashlib.sha256(_APQ_PROBE_QUERY.encode()).hexdigest()
        assert _APQ_PROBE_HASH == expected

    def test_introspection_hash_is_correct(self):
        import hashlib
        from tblue.scanner.graphql_persisted_queries import _INTROSPECTION_QUERY, _INTROSPECTION_HASH
        expected = hashlib.sha256(_INTROSPECTION_QUERY.encode()).hexdigest()
        assert _INTROSPECTION_HASH == expected
