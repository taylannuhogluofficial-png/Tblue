"""Tests for BroadcastChannelAdvancedSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.broadcast_channel_advanced_security import BroadcastChannelAdvancedSecurityScanner


def _scanner():
    s = BroadcastChannelAdvancedSecurityScanner.__new__(BroadcastChannelAdvancedSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_broadcast_channel_credentials_broadcast():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const bc = new BroadcastChannel('app')"
        "bc.postMessage({type: 'auth', token: authToken, password: pwd})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "broadcast_channel_credentials_broadcast" in types


def test_broadcast_channel_receive_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const bc = new BroadcastChannel('updates')"
        "bc.onmessage = (e) => sendBeacon('/relay', JSON.stringify(e.data))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "broadcast_channel_receive_exfil" in types


def test_broadcast_channel_sensitive_name():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const bc = new BroadcastChannel('auth')"
        "bc.onmessage = handler"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "broadcast_channel_sensitive_name" in types


def test_broadcast_channel_advanced_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No cross-tab communication here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "broadcast_channel_advanced_not_used"
    assert results[0]["status"] == "PASS"


def test_broadcast_channel_advanced_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "broadcast_channel_advanced_not_used"
