"""Extra branch coverage for tblue.scanner.websocket."""

from unittest.mock import MagicMock, patch
from tblue.scanner.websocket import WebSocketScanner

URL = "https://example.com"


def _resp(body="", status=200):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    r.url = URL
    return r


def _scanner():
    session = MagicMock()
    return WebSocketScanner(session)


def test_no_websocket_passes():
    """Page with no WebSocket usage → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html><body>No WS</body></html>")):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_insecure_ws_url_fails():
    """ws:// WebSocket connection on non-HTTPS page → FAIL."""
    s = _scanner()
    html = "<html><script>var ws = new WebSocket('ws://example.com/chat');</script></html>"
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad


def test_secure_wss_passes():
    """wss:// WebSocket connection → PASS."""
    s = _scanner()
    html = "<html><script>var ws = new WebSocket('wss://example.com/chat');</script></html>"
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_none_response_no_fail():
    """None response → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert all(r["status"] != "FAIL" for r in results)


def test_result_keys():
    """Results contain required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
