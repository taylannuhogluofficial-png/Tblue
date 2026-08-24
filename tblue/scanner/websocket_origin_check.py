"""WebSocket origin validation — missing origin check, ws:// on HTTPS pages."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_WS_ENDPOINT_RE = re.compile(
    r'(?:new\s+WebSocket\s*\(\s*["\'])(?P<url>wss?://[^"\']+)',
    re.I,
)
_WS_WITHOUT_ORIGIN_RE = re.compile(
    r'new\s+WebSocket\s*\([^)]+\)(?!.*?\.onopen)',
    re.I | re.S,
)

# Look for WebSocket creation without origin enforcement
_WS_NO_VALIDATION_RE = re.compile(
    r'new\s+WebSocket\([^)]+\).*?(?:\.onmessage\s*=\s*function)',
    re.I | re.S,
)


def _find_websocket_endpoints(body: str) -> list:
    """Extract ws:// and wss:// URLs from JavaScript source."""
    endpoints = []
    for m in _WS_ENDPOINT_RE.finditer(body):
        endpoints.append(m.group("url"))
    return endpoints


def _check_insecure_ws(endpoints: list, page_url: str) -> list:
    """Flag ws:// (non-TLS) endpoints on HTTPS pages."""
    findings = []
    is_https = page_url.startswith("https://")
    for ep in endpoints:
        if ep.startswith("ws://") and is_https:
            findings.append({
                "type": "websocket_insecure_ws_on_https",
                "status": "FAIL",
                "detail": f"Insecure WebSocket (ws://) found on HTTPS page: {ep[:80]}",
            })
        elif ep.startswith("ws://"):
            findings.append({
                "type": "websocket_insecure_protocol",
                "status": "WARN",
                "detail": f"WebSocket using unencrypted ws:// — upgrade to wss://: {ep[:80]}",
            })
    return findings


def _check_wildcard_cors_upgrade(headers: dict, url: str) -> dict | None:
    """Sec-WebSocket-* headers in response without origin control."""
    if "sec-websocket-accept" in {k.lower() for k in headers}:
        acao = headers.get("access-control-allow-origin", "")
        if acao == "*":
            return {
                "type": "websocket_wildcard_cors",
                "status": "WARN",
                "detail": "WebSocket upgrade response has ACAO: * — origin not validated",
            }
    return None


class WebSocketOriginCheckScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "ws_origin_no_response", "PASS",
                                 detail="No response")]

        body = resp.text

        # Scan page for WebSocket usage
        endpoints = _find_websocket_endpoints(body)
        for f in _check_insecure_ws(endpoints, url):
            results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        # Check headers from current response
        cors_issue = _check_wildcard_cors_upgrade(dict(resp.headers), url)
        if cors_issue:
            results.append(self._result(url, cors_issue["type"], cors_issue["status"],
                                        detail=cors_issue["detail"]))

        # Probe common WebSocket paths
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        for path in ["/ws", "/websocket", "/socket", "/realtime", "/live"]:
            r = self.http.get(origin + path)
            if r and r.status_code == 200:
                for f in _check_insecure_ws(_find_websocket_endpoints(r.text), url):
                    results.append(self._result(origin + path, f["type"], f["status"],
                                                detail=f["detail"]))

        if not results:
            results.append(self._result(url, "ws_origin_check_pass", "PASS",
                                        detail="No WebSocket origin validation issues detected"))
        return results
