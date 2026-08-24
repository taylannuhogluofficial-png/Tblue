"""Tests for GraphQL Batch Abuse scanner."""
from unittest.mock import MagicMock, patch
import json

URL = "https://example.com"


class TestGraphQLBatchAbuseScanner:
    def _scanner(self):
        from tblue.scanner.graphql_batch_abuse import GraphQLBatchAbuseScanner
        return GraphQLBatchAbuseScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_graphql_endpoint_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(status=404)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_graphql_endpoint_found_no_batching_passes(self):
        s = self._scanner()
        gql_resp = self._resp('{"data":{"__typename":"Query"}}', 200)
        non_batch = self._resp('{"data":{"__typename":"Query"}}', 200)
        non_batch.text = '{"data":{"__typename":"Query"}}'

        def get_side(url, **kwargs):
            if "graphql" in url:
                return gql_resp
            return self._resp(status=404)

        s.http.post = MagicMock(return_value=non_batch)
        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_array_batching_detected_warns(self):
        s = self._scanner()
        batch_body = json.dumps([
            {"data": {"__typename": "Query"}},
            {"data": {"__typename": "Query"}},
            {"data": {"__typename": "Query"}},
        ])

        def get_side(url, **kwargs):
            if "graphql" in url:
                return self._resp('{"data":{"__typename":"Query"}}', 200)
            return self._resp(status=404)

        s.http.post = MagicMock(return_value=self._resp(batch_body, 200))
        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("batch" in r["type"] for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(status=404)):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_find_graphql_endpoint(self):
        from tblue.scanner.graphql_batch_abuse import _find_graphql_endpoint
        http = MagicMock()
        r = MagicMock()
        r.status_code = 200
        http.get.return_value = r
        result = _find_graphql_endpoint(http, "https://example.com")
        assert result is not None
        assert "graphql" in result

    def test_find_graphql_endpoint_none(self):
        from tblue.scanner.graphql_batch_abuse import _find_graphql_endpoint
        http = MagicMock()
        r = MagicMock()
        r.status_code = 404
        http.get.return_value = r
        result = _find_graphql_endpoint(http, "https://example.com")
        assert result is None
