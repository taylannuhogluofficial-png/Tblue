"""WebSocket security deep — missing auth on WS upgrade, unencrypted ws://, message injection patterns."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_WS_UPGRADE_RE = re.compile(r'(?:new\s+WebSocket|io\s*\(|socket\.connect)\s*\(\s*["\']([^"\']+)["\']', re.I)
_WS_PLAIN_RE = re.compile(r'\bws://[^\s"\'<>]+', re.I)
_WS_SECURE_RE = re.compile(r'\bwss://[^\s"\'<>]+', re.I)
_AUTH_TOKEN_IN_WS_URL_RE = re.compile(r'wss?://[^\s"\']*[?&](?:token|auth|key|jwt|session)=', re.I)
_SOCKET_IO_RE = re.compile(r'socket\.io|io\.connect|socketio', re.I)


def _check_ws_endpoints_in_page(body: str, page_url: str) -> list:
    findings = []
    plain_ws = _WS_PLAIN_RE.findall(body)
    if plain_ws:
        for ws in plain_ws[:3]:
            findings.append({
                "type": "websocket_plain_ws_scheme",
                "status": "FAIL",
                "url": page_url,
                "detail": f"Unencrypted WebSocket (ws://) found: {ws[:80]} — "
                          "all WS communication should use wss:// to prevent MITM",
            })

    auth_ws = _AUTH_TOKEN_IN_WS_URL_RE.findall(body)
    if auth_ws:
        findings.append({
            "type": "websocket_token_in_url",
            "status": "WARN",
            "url": page_url,
            "detail": "WebSocket URL contains authentication token in query string — "
                      "tokens in URLs appear in server logs and browser history",
        })

    return findings


def _check_socketio_exposed(http, origin: str) -> list:
    findings = []
    for path in ["/socket.io/", "/socketio", "/ws/"]:
        try:
            r = http.get(origin + path)
            if r and r.status_code in (200, 400, 101):
                findings.append({
                    "type": "websocket_socketio_endpoint_exposed",
                    "status": "WARN",
                    "url": origin + path,
                    "detail": f"WebSocket/Socket.IO endpoint {path} accessible — "
                              "verify origin validation and authentication on upgrade handshake",
                })
                return findings
        except Exception:
            pass
    return findings


class WebSocketSecurityDeepScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "websocket_deep_no_response", "PASS", detail="No response")]

        for f in _check_ws_endpoints_in_page(resp.text, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        for f in _check_socketio_exposed(self.http, origin):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "websocket_deep_clean", "PASS",
                                        detail="No WebSocket security issues detected"))
        return results
