"""Tests for GraphQL Subscription Security scanner."""
import json
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestGraphQLSubscriptionScanner:
    def _scanner(self):
        from tblue.scanner.graphql_subscription import GraphQLSubscriptionScanner
        return GraphQLSubscriptionScanner(MagicMock())

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        r.url = URL
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            with patch.object(s.http, "post", return_value=None):
                results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_subscriptions_passes(self):
        """No subscription endpoints, no subscription JS → PASS."""
        s = self._scanner()
        not_found = self._resp("", 404)
        root = self._resp("<html><body>Hello</body></html>")

        def get_side(url, **kwargs):
            return root if url == URL else not_found

        def post_side(url, **kwargs):
            return not_found

        with patch.object(s.http, "get", side_effect=get_side):
            with patch.object(s.http, "post", side_effect=post_side):
                results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_subscription_introspection_warns(self):
        """Subscription introspection enabled → WARN."""
        s = self._scanner()
        introspection_data = {
            "data": {
                "__schema": {
                    "subscriptionType": {
                        "name": "Subscription",
                        "fields": [{"name": "messageAdded", "type": {"name": "Message", "kind": "OBJECT"}}]
                    }
                }
            }
        }
        not_found = self._resp("", 404)

        def get_side(url, **kwargs):
            if url == URL:
                return self._resp("<html></html>")
            return not_found

        def post_side(url, **kwargs):
            if "graphql" in url:
                return self._resp(json.dumps(introspection_data), 200)
            return not_found

        with patch.object(s.http, "get", side_effect=get_side):
            with patch.object(s.http, "post", side_effect=post_side):
                results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("introspection" in r["type"].lower() for r in warns)

    def test_legacy_protocol_warns(self):
        """Legacy graphql-ws protocol header → WARN."""
        s = self._scanner()
        not_found = self._resp("", 404)

        def get_side(url, **kwargs):
            if url == URL:
                return self._resp("<html></html>")
            if "graphql" in url:
                headers = {"sec-websocket-protocol": "graphql-ws"}
                return self._resp("", 101, headers)
            return not_found

        def post_side(url, **kwargs):
            return not_found

        with patch.object(s.http, "get", side_effect=get_side):
            with patch.object(s.http, "post", side_effect=post_side):
                results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("legacy" in r["type"].lower() or "protocol" in r["type"].lower() for r in warns)

    def test_subscription_client_in_js_warns(self):
        """useSubscription in page JS but no endpoint found → WARN."""
        s = self._scanner()
        not_found = self._resp("", 404)
        body_with_sub = "<script>const { data } = useSubscription(MESSAGES_SUB);</script>"

        def get_side(url, **kwargs):
            return self._resp(body_with_sub) if url == URL else not_found

        def post_side(url, **kwargs):
            return not_found

        with patch.object(s.http, "get", side_effect=get_side):
            with patch.object(s.http, "post", side_effect=post_side):
                results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("subscription" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        not_found = self._resp("", 404)
        with patch.object(s.http, "get", return_value=not_found):
            with patch.object(s.http, "post", return_value=not_found):
                results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_subscription_introspection_found(self):
        from tblue.scanner.graphql_subscription import _check_subscription_introspection
        r = MagicMock()
        r.status_code = 200
        r.text = json.dumps({
            "data": {"__schema": {"subscriptionType": {"name": "Sub", "fields": []}}}
        })
        f = _check_subscription_introspection(r)
        assert f is not None

    def test_check_subscription_introspection_not_found(self):
        from tblue.scanner.graphql_subscription import _check_subscription_introspection
        r = MagicMock()
        r.status_code = 200
        r.text = json.dumps({"data": {"__schema": {"subscriptionType": None}}})
        f = _check_subscription_introspection(r)
        assert f is None

    def test_check_subscription_in_page_source(self):
        from tblue.scanner.graphql_subscription import _check_subscription_in_page_source
        body = "const result = useSubscription(LIVE_UPDATES);"
        assert _check_subscription_in_page_source(body) is not None

    def test_no_subscription_in_page_source(self):
        from tblue.scanner.graphql_subscription import _check_subscription_in_page_source
        body = "const x = useQuery(GET_USERS);"
        assert _check_subscription_in_page_source(body) is None
