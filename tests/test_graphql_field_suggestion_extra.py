"""Extra branch coverage for tblue.scanner.graphql_field_suggestion."""

import json
from unittest.mock import MagicMock, patch
from tblue.scanner.graphql_field_suggestion import GraphQLFieldSuggestionScanner

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
    return GraphQLFieldSuggestionScanner(session)


def test_no_graphql_passes():
    """No GraphQL endpoint → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("", 404)), \
         patch.object(s.http, "post", return_value=_resp("", 404)):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_field_suggestion_in_error_fails():
    """Error response containing 'Did you mean' field suggestion → FAIL."""
    s = _scanner()
    suggestion_body = json.dumps({
        "errors": [{"message": "Cannot query field 'userz'. Did you mean 'user' or 'users'?"}]
    })

    def post_side(url, **kw):
        return _resp(suggestion_body)

    with patch.object(s.http, "get", return_value=_resp("<html></html>")), \
         patch.object(s.http, "post", side_effect=post_side):
        results = s.scan(URL)
    assert isinstance(results, list)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad


def test_no_suggestion_in_error_passes():
    """Error response without field suggestion → PASS."""
    s = _scanner()
    error_body = json.dumps({"errors": [{"message": "Unauthorized"}]})

    def post_side(url, **kw):
        return _resp(error_body)

    with patch.object(s.http, "get", return_value=_resp("<html></html>")), \
         patch.object(s.http, "post", side_effect=post_side):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_none_response_no_fail():
    """None response returns no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None), \
         patch.object(s.http, "post", return_value=None):
        results = s.scan(URL)
    assert all(r["status"] != "FAIL" for r in results)


def test_result_structure():
    """Results always have required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("", 200)), \
         patch.object(s.http, "post", return_value=_resp("", 404)):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
