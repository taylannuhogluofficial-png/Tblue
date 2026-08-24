"""Tests for MessageChannelSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.message_channel_security import MessageChannelSecurityScanner


def _scanner():
    s = MessageChannelSecurityScanner.__new__(MessageChannelSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestPortToWildcard:
    def test_port_to_wildcard_fails(self):
        s = _scanner()
        # _MC_PORT_TO_WILDCARD_RE: postMessage(...port...) , "*")
        body = "const ch = new MessageChannel()\nwindow.postMessage({port: ch.port2}, '*')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "message_channel_port_to_wildcard" in types


class TestSensitiveData:
    def test_sensitive_data_via_port_warns(self):
        s = _scanner()
        # _MC_SENSITIVE_DATA_RE: .port1.postMessage(...token...)
        body = "const ch = new MessageChannel()\nch.port1.postMessage({token: authToken})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "message_channel_sensitive_data" in types


class TestPortToUrlParam:
    def test_port_to_url_param_fails(self):
        s = _scanner()
        # _MC_PORT_TO_URL_PARAM_RE: searchParams ... postMessage ... port
        body = "const ch = new MessageChannel()\nconst dest = searchParams.get('target')\ndest.postMessage('hi', {transfer: [ch.port1]})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "message_channel_port_to_url_param_target" in types


class TestNotUsed:
    def test_no_message_channel_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "message_channel_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
