"""Tests for Content Negotiation Security scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestContentNegotiationScanner:
    def _scanner(self):
        from tblue.scanner.content_negotiation import ContentNegotiationScanner
        return ContentNegotiationScanner(MagicMock())

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
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_issues_passes(self):
        """Server returns fixed content-type regardless of Accept → PASS."""
        s = self._scanner()
        fixed_resp = self._resp("<html>ok</html>", 200,
                                headers={"content-type": "text/html"})
        with patch.object(s.http, "get", return_value=fixed_resp):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_accept_reflected_warns(self):
        """Server reflects custom Accept value in Content-Type → WARN."""
        s = self._scanner()
        root = self._resp("<html>ok</html>", 200)

        def get_side(url, headers=None, **kwargs):
            accept = (headers or {}).get("Accept", "")
            if "tbl9z7x" in accept:
                return self._resp("", 200, headers={"content-type": accept})
            return root

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("reflect" in r["type"].lower() or "accept" in r["type"].lower() for r in warns)

    def test_json_api_as_html_warns(self):
        """JSON API that wraps in HTML for Accept: text/html → WARN."""
        s = self._scanner()

        def get_side(url, headers=None, **kwargs):
            accept = (headers or {}).get("Accept", "")
            if "application/json" in accept:
                return self._resp('{"users":[]}', 200,
                                  headers={"content-type": "application/json"})
            if "text/html" in accept:
                return self._resp('<html><body><pre>{"users":[]}</pre></body></html>', 200,
                                  headers={"content-type": "text/html"})
            return self._resp("<html>ok</html>", 200)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("html" in r["type"].lower() or "json" in r["type"].lower() for r in warns)

    def test_jsonp_via_accept_warns(self):
        """JSONP response when Accept: application/javascript → WARN."""
        s = self._scanner()

        def get_side(url, headers=None, **kwargs):
            accept = (headers or {}).get("Accept", "")
            if "javascript" in accept:
                return self._resp('callback({"data": "value"})', 200,
                                  headers={"content-type": "application/javascript"})
            return self._resp("{}", 200, headers={"content-type": "application/json"})

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("jsonp" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_accept_reflection_detected(self):
        from tblue.scanner.content_negotiation import _check_accept_reflection
        http = MagicMock()
        resp = MagicMock()
        resp.headers = {"content-type": "application/x-tbl9z7x-probe"}
        resp.status_code = 200
        http.get.return_value = resp
        result = _check_accept_reflection(http, "https://example.com")
        assert result is not None
        assert "reflected" in result["type"].lower()

    def test_check_accept_reflection_not_detected(self):
        from tblue.scanner.content_negotiation import _check_accept_reflection
        http = MagicMock()
        resp = MagicMock()
        resp.headers = {"content-type": "text/html"}
        resp.status_code = 200
        http.get.return_value = resp
        result = _check_accept_reflection(http, "https://example.com")
        assert result is None

    def test_check_jsonp_detected(self):
        from tblue.scanner.content_negotiation import _check_jsonp_via_accept
        http = MagicMock()
        resp = MagicMock()
        resp.headers = {"content-type": "application/javascript"}
        resp.text = "myCallback({\"key\": \"value\"})"
        resp.status_code = 200
        http.get.return_value = resp
        result = _check_jsonp_via_accept(http, "https://example.com/api")
        assert result is not None

    def test_get_ct_strips_params(self):
        from tblue.scanner.content_negotiation import _get_ct
        resp = MagicMock()
        resp.headers = {"content-type": "application/json; charset=utf-8"}
        result = _get_ct(resp)
        assert result == "application/json"

    def test_get_ct_none(self):
        from tblue.scanner.content_negotiation import _get_ct
        result = _get_ct(None)
        assert result == ""
