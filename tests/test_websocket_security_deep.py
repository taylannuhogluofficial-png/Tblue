"""Tests for WebSocket Security Deep scanner."""
from unittest.mock import MagicMock, patch
URL = "https://example.com"

class TestWebSocketSecurityDeepScanner:
    def _scanner(self):
        from tblue.scanner.websocket_security_deep import WebSocketSecurityDeepScanner
        return WebSocketSecurityDeepScanner(MagicMock())
    def _resp(self, body="OK", status=200, headers=None):
        r = MagicMock(); r.text = body; r.status_code = status; r.headers = headers or {}; return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None): results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_ws_plain_fails(self):
        from tblue.scanner.websocket_security_deep import _check_ws_endpoints_in_page
        findings = _check_ws_endpoints_in_page('new WebSocket("ws://example.com/chat")', URL)
        assert any("plain_ws" in f["type"] for f in findings)

    def test_wss_passes(self):
        from tblue.scanner.websocket_security_deep import _check_ws_endpoints_in_page
        findings = _check_ws_endpoints_in_page('new WebSocket("wss://example.com/chat")', URL)
        fails = [f for f in findings if f["status"] == "FAIL"]
        assert not fails

    def test_token_in_ws_url_warns(self):
        from tblue.scanner.websocket_security_deep import _check_ws_endpoints_in_page
        findings = _check_ws_endpoints_in_page('new WebSocket("wss://example.com/ws?token=abc123")', URL)
        assert any("token_in_url" in f["type"] for f in findings)

    def test_socketio_endpoint_warns(self):
        from tblue.scanner.websocket_security_deep import _check_socketio_exposed
        http = MagicMock(); r = MagicMock(); r.status_code = 200; r.text = "OK"
        http.get.return_value = r
        findings = _check_socketio_exposed(http, "https://example.com")
        assert any("socketio" in f["type"] for f in findings)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>clean</html>", 404)):
            results = s.scan(URL)
        for r in results: assert r["status"] in ("PASS", "WARN", "FAIL")
