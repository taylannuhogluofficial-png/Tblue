"""Tests for GraphQL Info Disclosure scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestGraphQLInfoDisclosureScanner:
    def _scanner(self):
        from tblue.scanner.graphql_info_disclosure import GraphQLInfoDisclosureScanner
        return GraphQLInfoDisclosureScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {"content-type": "application/json"}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_site_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>OK</html>")):
            with patch.object(s.http, "post", return_value=self._resp('{"data": null}', 404)):
                results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_field_suggestion_warns(self):
        s = self._scanner()
        body = '{"errors": [{"message": "Cannot query field \\"user\\". Did you mean \\"users\\"?"}]}'

        with patch.object(s.http, "get", return_value=self._resp("{}")):
            with patch.object(s.http, "post", return_value=self._resp(body, 200)):
                results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("suggestion" in r["type"] or "field" in r["type"] for r in warns)

    def test_stack_trace_in_gql_error_fails(self):
        s = self._scanner()
        body = '{"errors": [{"message": "Error", "extensions": {"exception": {"stacktrace": ["Error at ..."] }}}]}'

        with patch.object(s.http, "get", return_value=self._resp("{}")):
            with patch.object(s.http, "post", return_value=self._resp(body, 200)):
                results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("stack" in r["type"] for r in fails)

    def test_typename_exposed_warns(self):
        s = self._scanner()
        body = '{"data": {"__typename": "Query"}}'

        with patch.object(s.http, "get", return_value=self._resp("{}")):
            with patch.object(s.http, "post", return_value=self._resp(body, 200)):
                results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("typename" in r["type"] for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            with patch.object(s.http, "post", return_value=self._resp('{"data": null}', 404)):
                results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
