"""Tests for GraphQLBatchAttackScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.graphql_batch_attack import GraphQLBatchAttackScanner

URL = "https://example.com"


class TestGraphQLBatchAttack(unittest.TestCase):
    def _make(self):
        s = GraphQLBatchAttackScanner.__new__(GraphQLBatchAttackScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = headers or {}
        return r

    def _not_found(self):
        return self._resp("Not Found", 404)

    def _gql_base_side(self, extra=None):
        """Return a side_effect that answers /graphql with a basic GQL error (endpoint found)."""
        def side(url, **kw):
            if url == "https://example.com/graphql":
                return self._resp('{"errors":[{"message":"Must provide query"}]}', 400)
            if extra and url in extra:
                return extra[url]
            return self._not_found()
        return side

    # ── Endpoint not found ────────────────────────────────────────────────────

    def test_no_graphql_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._not_found()
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── Batching ──────────────────────────────────────────────────────────────

    def test_batching_enabled_warns(self):
        def side(url, **kw):
            if url == "https://example.com/graphql":
                body = kw.get("data", "")
                if isinstance(body, str) and body.strip().startswith("["):
                    return self._resp('[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]')
                return self._resp('{"errors":[{"message":"Must provide query"}]}', 400)
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("batch" in r["type"].lower() for r in warns))

    # ── Alias flooding ────────────────────────────────────────────────────────

    def test_alias_flooding_warns(self):
        def side(url, **kw):
            if url == "https://example.com/graphql":
                data = kw.get("data", "")
                if "a0:" in str(data):
                    return self._resp(
                        '{"data":{"a0":"Query","a1":"Query","a2":"Query","a3":"Query","a4":"Query",'
                        '"a5":"Query","a6":"Query","a7":"Query","a8":"Query","a9":"Query"}}'
                    )
                return self._resp('{"errors":[{"message":"query"}]}', 400)
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("alias" in r["type"].lower() for r in warns))

    # ── IDE exposure ──────────────────────────────────────────────────────────

    def test_graphiql_exposed_fails(self):
        def side(url, **kw):
            if url == "https://example.com/graphql":
                hdrs = kw.get("headers", {})
                if hdrs.get("Accept") == "text/html":
                    return self._resp('<html><title>GraphiQL</title><body>graphiql</body></html>')
                return self._resp('{"errors":[{"message":"query"}]}', 400)
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("ide" in r["type"].lower() or "graphiql" in r["type"].lower() or "ide" in r["type"].lower() for r in fails))

    # ── GET execution ─────────────────────────────────────────────────────────

    def test_get_execution_warns(self):
        def side(url, **kw):
            if url == "https://example.com/graphql":
                return self._resp('{"errors":[{"message":"query"}]}', 400)
            if "graphql?query" in url or "__typename" in url:
                return self._resp('{"data":{"__typename":"Query"}}')
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("get" in r["type"].lower() or "csrf" in r["type"].lower() for r in warns))

    # ── Introspection ─────────────────────────────────────────────────────────

    def test_introspection_warns(self):
        def side(url, **kw):
            if url == "https://example.com/graphql":
                data = kw.get("data", "")
                if "__schema" in str(data):
                    return self._resp('{"data":{"__schema":{"queryType":{"name":"Query"}}}}')
                return self._resp('{"errors":[{"message":"query"}]}', 400)
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("introspection" in r["type"].lower() for r in warns))

    # ── Clean ─────────────────────────────────────────────────────────────────

    def test_clean_graphql_passes(self):
        def side(url, **kw):
            if url == "https://example.com/graphql":
                return self._resp('{"errors":[{"message":"Must provide query"}]}', 400)
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        # All checks returned nothing bad, should have PASS
        self.assertTrue(any(r["status"] == "PASS" for r in results))
