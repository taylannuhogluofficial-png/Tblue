"""Tests for ChannelMessagingSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.channel_messaging_security import ChannelMessagingSecurityScanner


def _scanner():
    s = ChannelMessagingSecurityScanner.__new__(ChannelMessagingSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_channel_messaging_sensitive_payload():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const channel = new MessageChannel()\n"
        "channel.port1.postMessage({token: userToken, secret: apiSecret})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "channel_messaging_sensitive_payload" in types


def test_channel_messaging_unsafe_handler():
    s = _scanner()
    s.http.get.return_value = _resp(
        "port.onmessage = (e) => {\n"
        "  document.body.innerHTML = e.data\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "channel_messaging_unsafe_message_handler" in types


def test_channel_messaging_exfil_via_port():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const channel = new MessageChannel()\n"
        "const data = channel.port1\n"
        "sendBeacon('/exfil', JSON.stringify(data))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "channel_messaging_exfil_via_port" in types


def test_channel_messaging_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No channel or port messaging API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "channel_messaging_not_used"
    assert results[0]["status"] == "PASS"


def test_channel_messaging_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "channel_messaging_not_used"
