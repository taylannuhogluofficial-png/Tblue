"""Tests for ServerSentEventsSecurityScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.server_sent_events_security import ServerSentEventsSecurityScanner


def _scanner():
    s = ServerSentEventsSecurityScanner.__new__(ServerSentEventsSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestSSECORSWildcard:
    def test_sse_cors_wildcard_fails(self):
        s = _scanner()
        sse_headers = {
            "content-type": "text/event-stream",
            "access-control-allow-origin": "*",
            "cache-control": "no-store",
        }
        sse_resp = _resp(200, "data: {\"msg\":\"hello\"}\n\n", sse_headers)

        def side_effect(url):
            if "/events" in url:
                return sse_resp
            return _resp(200, "<html>ok</html>", {})

        s.http.get.side_effect = side_effect
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "sse_cors_wildcard" in types

    def test_specific_cors_origin_passes(self):
        s = _scanner()
        sse_headers = {
            "content-type": "text/event-stream",
            "access-control-allow-origin": "https://example.com",
            "cache-control": "no-store",
        }
        sse_resp = _resp(200, "data: hello\n\n", sse_headers)

        def side_effect(url):
            if "/events" in url:
                return sse_resp
            return _resp(200, "<html>ok</html>", {})

        s.http.get.side_effect = side_effect
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "sse_cors_wildcard" not in types


class TestSSECacheable:
    def test_sse_cacheable_warns(self):
        s = _scanner()
        sse_headers = {
            "content-type": "text/event-stream",
            "cache-control": "public, max-age=3600",
        }
        sse_resp = _resp(200, "data: hello\n\n", sse_headers)

        def side_effect(url):
            if "/events" in url:
                return sse_resp
            return _resp(200, "<html>ok</html>", {})

        s.http.get.side_effect = side_effect
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "sse_cacheable_stream" in types

    def test_no_store_passes(self):
        s = _scanner()
        sse_headers = {
            "content-type": "text/event-stream",
            "cache-control": "no-store",
        }
        sse_resp = _resp(200, "data: hello\n\n", sse_headers)

        def side_effect(url):
            if "/events" in url:
                return sse_resp
            return _resp(200, "<html>ok</html>", {})

        s.http.get.side_effect = side_effect
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "sse_cacheable_stream" not in types


class TestSSESensitiveData:
    def test_sensitive_data_in_stream_fails(self):
        s = _scanner()
        sse_body = 'data: {"email": "user@example.com", "token": "abc123"}\n\n'
        sse_headers = {
            "content-type": "text/event-stream",
            "cache-control": "no-store",
        }
        sse_resp = _resp(200, sse_body, sse_headers)

        def side_effect(url):
            if "/events" in url:
                return sse_resp
            return _resp(200, "<html>ok</html>", {})

        s.http.get.side_effect = side_effect
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "sse_sensitive_data_in_stream" in types


class TestSSENotFound:
    def test_no_sse_endpoint_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(404, "Not Found", {})
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "sse_not_found" in types

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
