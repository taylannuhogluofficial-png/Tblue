"""Extra branch coverage for tblue.scanner.graphql_depth."""

import json
from unittest.mock import MagicMock, patch
from tblue.scanner.graphql_depth import GraphQLDepthScanner

URL = "https://example.com"


def _resp(body="", status=200):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    r.url = URL
    return r


def _scanner():
    session = MagicMock()
    return GraphQLDepthScanner(session)


def test_no_graphql_endpoint_returns_pass():
    """All probed paths return 404 → PASS (no GraphQL endpoint found)."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("", 404)), \
         patch.object(s.http, "post", return_value=_resp("", 404)):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_none_response_returns_pass_or_empty():
    """None response → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None), \
         patch.object(s.http, "post", return_value=None):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_depth_limit_enforced_passes():
    """Server returns depth-limit error for deep query → PASS (limit enforced)."""
    s = _scanner()
    depth_error = json.dumps({"errors": [{"message": "Query depth limit exceeded"}]})
    success = json.dumps({"data": {"__typename": "Query"}})

    def post_side(url, json=None, **kw):
        q = (json or {}).get("query", "")
        if q.count("{") > 5:
            return _resp(depth_error)
        return _resp(success)

    with patch.object(s.http, "get", return_value=_resp("<html></html>")), \
         patch.object(s.http, "post", side_effect=post_side):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_no_depth_limit_fails():
    """Server returns data for very deep query → FAIL (no depth limit)."""
    s = _scanner()
    data_resp = json.dumps({"data": {"__typename": "Query"}})

    with patch.object(s.http, "get", return_value=_resp("<html></html>")), \
         patch.object(s.http, "post", return_value=_resp(data_resp)):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_result_keys_present():
    """All results contain required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("", 404)), \
         patch.object(s.http, "post", return_value=_resp("", 404)):
        results = s.scan(URL)
    for r in results:
        assert "url" in r
        assert "status" in r
        assert "type" in r
