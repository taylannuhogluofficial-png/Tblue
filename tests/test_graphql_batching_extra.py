"""Extra edge-case tests for GraphQLBatchingScanner."""
import json
from unittest.mock import MagicMock, patch

from tblue.scanner.graphql_batching import GraphQLBatchingScanner

URL = "https://example.com"
GQL_EP = "https://example.com/graphql"


def _session():
    return MagicMock()


def _scanner():
    return GraphQLBatchingScanner(_session())


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.text = body
    r.status_code = status
    r.headers = headers or {}
    r.url = URL
    return r


# ── Endpoint discovery via page source ───────────────────────────────────────

def test_graphql_endpoint_hint_in_page_source():
    """Scanner finds GraphQL endpoint mentioned in page HTML when common-path probes fail."""
    from tblue.scanner.graphql_batching import _GRAPHQL_PATHS
    s = _scanner()
    # Page source mentions /graphql
    html = '<html><body><script>var api="/graphql";</script></body></html>'
    gql_body = '{"data":{"__typename":"Query"}}'

    outer_call_count = {"n": 0}

    def post_side(url, **kw):
        outer_call_count["n"] += 1
        # First N calls (outer path loop) all fail; inner loop re-tries and succeeds
        if outer_call_count["n"] <= len(_GRAPHQL_PATHS):
            return _resp("", 404)
        # Inner loop second chance for /graphql
        if "/graphql" in url:
            return _resp(gql_body, 200)
        return _resp("", 404)

    def get_side(url, **kw):
        return _resp(html, 200)

    with patch.object(s.http, "post", side_effect=post_side), \
         patch.object(s.http, "get", side_effect=get_side):
        endpoints = s._discover_endpoints(URL, "https://example.com")
    assert endpoints


def test_no_endpoint_in_source_returns_empty():
    """No GraphQL references in page and no common paths respond → empty list."""
    s = _scanner()
    with patch.object(s.http, "post", return_value=_resp("", 404)), \
         patch.object(s.http, "get", return_value=_resp("<html></html>", 200)):
        endpoints = s._discover_endpoints(URL, "https://example.com")
    assert endpoints == []


# ── Partial batch response ────────────────────────────────────────────────────

def test_partial_batch_only_one_data_not_flagged():
    """If only one item in batch has 'data', don't flag as FAIL."""
    s = _scanner()
    # Only first has 'data', second has 'errors'
    body = '[{"data":{"__typename":"Query"}},{"errors":[{"message":"unauthorized"}]}]'
    with patch.object(s.http, "post", return_value=_resp(body, 200)):
        s._check_batching(GQL_EP)
    fails = [r for r in s.results if r["status"] == "FAIL"]
    assert not fails


def test_non_json_batch_response_is_silent():
    """Non-JSON batch response doesn't crash."""
    s = _scanner()
    with patch.object(s.http, "post", return_value=_resp("<html>error</html>", 200)):
        s._check_batching(GQL_EP)
    # Should not have raised, results may be empty or pass
    for r in s.results:
        assert r["status"] in ("PASS", "WARN", "FAIL")


# ── Alias count boundary ──────────────────────────────────────────────────────

def test_fewer_aliases_returned_not_flagged():
    """If server returns fewer aliases than sent, don't flag."""
    s = _scanner()
    # Return only 3 alias fields (sent 10)
    data = {"data": {f"a{i}": "Query" for i in range(3)}}
    with patch.object(s.http, "post", return_value=_resp(json.dumps(data), 200)):
        s._check_alias_multiplication(GQL_EP)
    warns = [r for r in s.results if r["status"] == "WARN"]
    assert not warns


def test_exactly_alias_count_returned_warns():
    """Return exactly ALIAS_COUNT (10) aliases → WARN."""
    from tblue.scanner.graphql_batching import _ALIAS_COUNT
    s = _scanner()
    data = {"data": {f"a{i}": "Query" for i in range(_ALIAS_COUNT)}}
    with patch.object(s.http, "post", return_value=_resp(json.dumps(data), 200)):
        s._check_alias_multiplication(GQL_EP)
    warns = [r for r in s.results if r["status"] in ("WARN", "FAIL")]
    assert warns


# ── Multiple endpoints (only one found due to break) ─────────────────────────

def test_only_first_graphql_path_checked():
    """Scanner stops at the first live endpoint found."""
    s = _scanner()
    call_count = {"n": 0}
    gql_body = '{"data":{"__typename":"Query"}}'

    def post_side(url, **kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _resp(gql_body, 200)
        return _resp("", 404)

    endpoints = []
    with patch.object(s.http, "post", side_effect=post_side):
        endpoints = s._discover_endpoints(URL, "https://example.com")

    assert len(endpoints) == 1


# ── Full scan via discovered endpoints ───────────────────────────────────────

def test_full_scan_with_live_endpoint_runs_checks():
    """Full scan finds endpoint and runs all three checks."""
    s = _scanner()
    gql_body = '{"data":{"__typename":"Query"}}'

    def post_side(url, json=None, **kw):
        if isinstance(json, list):
            # Batch probe — reject (PASS)
            return _resp('[{"errors":[{"message":"batching not allowed"}]}]', 200)
        # Introspection and alias probes
        return _resp(gql_body, 200)

    with patch.object(s.http, "post", side_effect=post_side):
        results = s.scan(URL)

    # Should have results from all three checks (batch PASS, alias, rate limit)
    assert results
    types = [r["type"] for r in results]
    assert any("rate limit" in t.lower() for t in types)


def test_alias_non_dict_data_not_flagged():
    """If response 'data' field is not a dict, don't flag alias multiplication."""
    s = _scanner()
    # data is a string, not a dict
    data = {"data": "typename"}
    with patch.object(s.http, "post", return_value=_resp(json.dumps(data), 200)):
        s._check_alias_multiplication(GQL_EP)
    warns = [r for r in s.results if r["status"] == "WARN"]
    assert not warns


def test_alias_json_parse_error_is_silent():
    """Malformed JSON in alias response doesn't crash."""
    s = _scanner()
    with patch.object(s.http, "post", return_value=_resp("not json at all {}", 200)):
        s._check_alias_multiplication(GQL_EP)
    # Should not have raised


# ── Scan integration ──────────────────────────────────────────────────────────

def test_full_scan_no_graphql_returns_pass():
    """Full scan with no GraphQL endpoint → PASS."""
    s = _scanner()
    with patch.object(s.http, "post", return_value=_resp("", 404)), \
         patch.object(s.http, "get", return_value=_resp("<html></html>", 200)):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_full_scan_with_rate_limit_warns():
    """Full scan with live GraphQL but no rate-limit headers → WARN."""
    s = _scanner()
    gql_body = '{"data":{"__typename":"Query"}}'

    call_count = {"n": 0}

    def post_side(url, json=None, **kw):
        if isinstance(json, list):
            # Batch probe — return single item (not flagged)
            return _resp('[{"errors":[{"message":"Batching not allowed"}]}]', 200)
        # Introspection / alias probes
        return _resp(gql_body, 200)

    def get_side(url, **kw):
        return _resp(gql_body, 200)

    with patch.object(s.http, "post", side_effect=post_side), \
         patch.object(s.http, "get", side_effect=get_side):
        # Manually call with known endpoint
        s._check_rate_limit_headers(GQL_EP)

    warns = [r for r in s.results if r["status"] == "WARN"]
    assert warns
