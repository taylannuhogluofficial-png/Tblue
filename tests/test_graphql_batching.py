"""Tests for GraphQLBatchingScanner."""
import json
from unittest.mock import MagicMock, patch

import pytest

from tblue.scanner.graphql_batching import GraphQLBatchingScanner

URL = "https://example.com"
GQL_EP = "https://example.com/graphql"


def _session():
    return MagicMock()


def _scanner():
    s = GraphQLBatchingScanner(_session())
    return s


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.text = body
    r.status_code = status
    r.headers = headers or {}
    r.url = URL
    return r


def _gql_resp(data):
    return _resp(json.dumps(data))


# ── Endpoint discovery ────────────────────────────────────────────────────────

class TestEndpointDiscovery:
    def test_no_graphql_endpoint_returns_pass(self):
        s = _scanner()
        with patch.object(s.http, "post", return_value=_resp("not graphql", 404)), \
             patch.object(s.http, "get", return_value=_resp("<html></html>")):
            results = s.scan(URL)
        assert results
        assert any(r["status"] == "PASS" for r in results)

    def test_graphql_endpoint_found_via_post(self):
        s = _scanner()
        # First POST to /graphql returns {"data": {"__typename": "Query"}}
        gql_body = '{"data":{"__typename":"Query"}}'
        not_found = _resp("", 404)

        def post_side(url, **kw):
            if "/graphql" in url:
                return _resp(gql_body, 200)
            return not_found

        with patch.object(s.http, "post", side_effect=post_side):
            endpoints = s._discover_endpoints(URL, "https://example.com")
        assert endpoints


# ── Batching checks ───────────────────────────────────────────────────────────

class TestBatchingCheck:
    def _scanner_with_endpoint(self):
        s = _scanner()
        return s

    def test_batch_accepted_fails(self):
        s = self._scanner_with_endpoint()
        batch_response = [
            {"data": {"__typename": "Query"}},
            {"data": {"__typename": "Query"}},
        ]
        rate_limit_check = _resp("no limit error", 200)

        def post_side(url, json=None, **kw):
            if isinstance(json, list) and len(json) == 2:
                return _resp(batch_response.__str__().replace("'", '"'), 200)
            # For alias/rate-limit checks
            return _resp('{"data":{"__typename":"Query"}}', 200)

        with patch.object(s.http, "post", return_value=_resp(
            '[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]', 200
        )):
            s._check_batching(GQL_EP)

        fails = [r for r in s.results if r["status"] == "FAIL"]
        assert fails

    def test_batch_rejected_passes(self):
        s = _scanner()
        with patch.object(s.http, "post", return_value=_resp(
            '{"errors":[{"message":"Batching not allowed"}]}', 200
        )):
            s._check_batching(GQL_EP)
        passes = [r for r in s.results if r["status"] == "PASS"]
        assert passes

    def test_batch_none_response_is_silent(self):
        s = _scanner()
        with patch.object(s.http, "post", return_value=None):
            s._check_batching(GQL_EP)
        assert s.results == []

    def test_batch_rate_limit_error_in_body_passes(self):
        s = _scanner()
        with patch.object(s.http, "post", return_value=_resp(
            '{"errors":[{"message":"Query complexity exceeded rate limit"}]}', 200
        )):
            s._check_batching(GQL_EP)
        assert any(r["status"] == "PASS" for r in s.results)


# ── Alias multiplication checks ───────────────────────────────────────────────

class TestAliasMultiplication:
    def test_alias_multiplication_warns(self):
        s = _scanner()
        # Return 10 alias fields in data
        data = {"data": {f"a{i}": "Query" for i in range(10)}}
        with patch.object(s.http, "post", return_value=_gql_resp(data)):
            s._check_alias_multiplication(GQL_EP)
        warns = [r for r in s.results if r["status"] in ("WARN", "FAIL")]
        assert warns

    def test_alias_complexity_error_passes(self):
        s = _scanner()
        with patch.object(s.http, "post", return_value=_resp(
            '{"errors":[{"message":"Alias limit exceeded"}]}', 200
        )):
            s._check_alias_multiplication(GQL_EP)
        passes = [r for r in s.results if r["status"] == "PASS"]
        assert passes

    def test_alias_none_response_is_silent(self):
        s = _scanner()
        with patch.object(s.http, "post", return_value=None):
            s._check_alias_multiplication(GQL_EP)
        assert s.results == []


# ── Rate limit header checks ──────────────────────────────────────────────────

class TestRateLimitHeaders:
    def test_rate_limit_header_present_passes(self):
        s = _scanner()
        with patch.object(s.http, "post", return_value=_resp(
            '{"data":{"__typename":"Query"}}', 200,
            headers={"X-RateLimit-Limit": "100"}
        )):
            s._check_rate_limit_headers(GQL_EP)
        passes = [r for r in s.results if r["status"] == "PASS"]
        assert passes

    def test_no_rate_limit_header_warns(self):
        s = _scanner()
        with patch.object(s.http, "post", return_value=_resp(
            '{"data":{"__typename":"Query"}}', 200
        )):
            s._check_rate_limit_headers(GQL_EP)
        warns = [r for r in s.results if r["status"] == "WARN"]
        assert warns

    def test_retry_after_header_passes(self):
        s = _scanner()
        with patch.object(s.http, "post", return_value=_resp(
            '{"data":{}}', 200, headers={"Retry-After": "60"}
        )):
            s._check_rate_limit_headers(GQL_EP)
        assert any(r["status"] == "PASS" for r in s.results)

    def test_none_response_is_silent(self):
        s = _scanner()
        with patch.object(s.http, "post", return_value=None):
            s._check_rate_limit_headers(GQL_EP)
        assert s.results == []


# ── Result structure ──────────────────────────────────────────────────────────

class TestResultStructure:
    def test_result_has_required_keys(self):
        s = _scanner()
        with patch.object(s.http, "post", return_value=_resp("", 404)), \
             patch.object(s.http, "get", return_value=_resp("<html></html>")):
            results = s.scan(URL)
        assert results
        for r in results:
            assert "url" in r
            assert "type" in r
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")
