"""Tests for Server-Sent Events security scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestSSESecurityScanner:
    def _scanner(self):
        from tblue.scanner.sse_security import SSESecurityScanner
        return SSESecurityScanner(MagicMock())

    def _resp(self, body="", headers=None, status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        r.url = URL
        return r

    def _sse_resp(self, acao="", status=200, scheme="https"):
        r = MagicMock()
        r.text = "data: hello\n\n"
        r.status_code = status
        headers = {"content-type": "text/event-stream; charset=utf-8"}
        if acao:
            headers["access-control-allow-origin"] = acao
        r.headers = headers
        r.url = (scheme + "://example.com/events")
        return r

    def test_no_sse_endpoints_passes(self):
        """No SSE endpoints found → PASS."""
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>no events</html>")):
            results = s.scan(URL)
        assert any("no EventSource" in r["type"] or "no Server-Sent" in r["type"] for r in results)
        assert all(r["status"] == "PASS" for r in results)

    def test_sse_endpoint_detected_by_eventsource_in_source(self):
        """EventSource('/stream') in page source → /stream probed as SSE."""
        s = self._scanner()
        page_resp = self._resp('<script>new EventSource("/events")</script>')
        sse_resp = self._sse_resp()

        def get_side(url):
            if "/events" in url:
                return sse_resp
            return page_resp

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        # Should have found the SSE endpoint and produced at least one result about it
        types = " ".join(r["type"] for r in results)
        assert "EventSource" in types or "SSE" in types

    def test_wildcard_cors_on_sse_fails(self):
        """SSE endpoint with ACAO: * → FAIL."""
        s = self._scanner()
        page_resp = self._resp("<html></html>")
        sse_resp = self._sse_resp(acao="*")

        def get_side(url):
            if "/events" in url:
                return sse_resp
            return page_resp

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("wildcard" in r["type"].lower() or "Allow-Origin" in r["type"] for r in fails)

    def test_sse_endpoint_requires_auth_passes(self):
        """SSE endpoint returns 401 → correctly protected (discovered via EventSource ref)."""
        s = self._scanner()
        # Page source references EventSource so the scanner tries to probe /events
        page_resp = self._resp('<script>new EventSource("/events")</script>')
        # When probing /events, return 401 with text/event-stream (auth-gated stream)
        auth_resp = self._resp("", {"content-type": "text/event-stream"}, status=401)

        def get_side(url):
            if "/events" in url and "example.com" not in url.split("/events")[0]:
                return auth_resp
            if "/events" in url:
                return auth_resp
            return page_resp

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        passes = [r for r in results if r["status"] == "PASS"]
        assert any("authentication" in r["type"].lower() or "401" in r["type"] for r in passes)

    def test_missing_no_store_warns(self):
        """SSE without Cache-Control: no-store → WARN."""
        s = self._scanner()
        page_resp = self._resp("<html></html>")
        sse_resp = self._sse_resp(acao="https://example.com")
        # No cache-control header
        sse_resp.headers.pop("cache-control", None)

        def get_side(url):
            if "/events" in url:
                return sse_resp
            return page_resp

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("no-store" in r["type"].lower() or "Cache-Control" in r["type"] for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html></html>")):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")
