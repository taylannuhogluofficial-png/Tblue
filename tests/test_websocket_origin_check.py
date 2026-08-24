"""Tests for WebSocket Origin Check scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestWebSocketOriginCheckScanner:
    def _scanner(self):
        from tblue.scanner.websocket_origin_check import WebSocketOriginCheckScanner
        return WebSocketOriginCheckScanner(MagicMock())

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_page_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>OK</html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_ws_on_https_fails(self):
        s = self._scanner()
        body = 'var ws = new WebSocket("ws://example.com/socket");'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("insecure_ws" in r["type"] for r in fails)

    def test_wss_passes(self):
        s = self._scanner()
        body = 'var ws = new WebSocket("wss://example.com/socket");'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        assert not any(r["status"] == "FAIL" and "insecure" in r["type"] for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_find_ws_endpoints(self):
        from tblue.scanner.websocket_origin_check import _find_websocket_endpoints
        body = 'new WebSocket("wss://example.com/socket")'
        assert "wss://example.com/socket" in _find_websocket_endpoints(body)

    def test_find_no_endpoints(self):
        from tblue.scanner.websocket_origin_check import _find_websocket_endpoints
        assert _find_websocket_endpoints("<html>OK</html>") == []

    def test_insecure_ws_on_https(self):
        from tblue.scanner.websocket_origin_check import _check_insecure_ws
        findings = _check_insecure_ws(["ws://example.com/socket"], "https://example.com")
        assert any("insecure_ws_on_https" in f["type"] for f in findings)

    def test_wss_no_finding(self):
        from tblue.scanner.websocket_origin_check import _check_insecure_ws
        assert _check_insecure_ws(["wss://example.com/socket"], "https://example.com") == []
