"""Tests for GraphQLCSRFScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.graphql_csrf import GraphQLCSRFScanner, _is_graphql_response

URL = "https://example.com"

_GQL_RESP = '{"data": {"__typename": "Query"}}'
_GQL_ERROR = '{"errors": [{"message": "Validation error"}]}'


class TestGraphQLCSRF:
    def _scanner(self):
        return GraphQLCSRFScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        return r

    def test_no_graphql_endpoint_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("Not Found", status=404)):
            results = s.scan(URL)
        assert any("no_endpoint" in r["type"] for r in results)
        assert any(r["status"] == "PASS" for r in results)

    def test_get_mutation_accepted_fails(self):
        from tblue.scanner.graphql_csrf import _check_get_mutation
        http = MagicMock()
        http.get.return_value = self._resp(_GQL_RESP)
        findings = _check_get_mutation(http, "https://example.com/graphql")
        assert any("get_mutation" in f["type"] for f in findings)

    def test_form_urlencoded_accepted_warns(self):
        from tblue.scanner.graphql_csrf import _check_form_urlencoded
        http = MagicMock()
        http.get.return_value = self._resp(_GQL_RESP)
        findings = _check_form_urlencoded(http, "https://example.com/graphql")
        assert any("form_urlencoded" in f["type"] for f in findings)

    def test_no_csrf_header_check_warns(self):
        from tblue.scanner.graphql_csrf import _check_missing_csrf_header
        http = MagicMock()
        http.get.return_value = self._resp(_GQL_RESP)
        findings = _check_missing_csrf_header(http, "https://example.com/graphql")
        assert any("no_header_check" in f["type"] for f in findings)

    def test_is_graphql_response_detects_data(self):
        assert _is_graphql_response('{"data": {"users": []}}')

    def test_is_graphql_response_detects_errors(self):
        assert _is_graphql_response('{"errors": [{"message": "Not found"}]}')

    def test_is_graphql_response_rejects_html(self):
        assert not _is_graphql_response("<html><body>Not Found</body></html>")

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("", status=404)):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
