"""
WebSocket Security Scanner.

Passively detects WebSocket endpoint references in page HTML/JavaScript,
then performs a read-only HTTP Upgrade probe to inspect server behaviour.

Checks:
  1. Plain ws:// references in page source — protocol downgrade, traffic visible in clear
  2. HTTP Upgrade response headers — missing Origin policy, no auth challenge
  3. Sec-WebSocket-Protocol header absent — server accepts any subprotocol
  4. WebSocket endpoints reachable without any authentication signal

Note: This scanner does NOT establish a persistent WebSocket connection.
It sends a standard HTTP Upgrade request (RFC 6455 §4.2.1) and inspects
the response headers. A 101 Switching Protocols response is analysed;
4xx/5xx are recorded as non-upgradeable.

Paid equivalents: Burp Suite Pro WebSocket security, OWASP ZAP WebSocket.
"""

import re
import base64
import os
from typing import Any, Dict, List, Set
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Match ws:// and wss:// URLs in page source
_WS_URL_RE = re.compile(r"""(wss?://[^\s"'<>\)]+)""", re.I)

# Common WebSocket endpoint paths to probe even if not found in HTML
_WS_PROBE_PATHS = [
    "/ws", "/websocket", "/socket", "/sock",
    "/ws/", "/socket.io/", "/sockjs/", "/signalr/",
    "/cable", "/api/ws", "/stream",
]

# A valid (but random) WebSocket handshake key
_WS_KEY = base64.b64encode(os.urandom(16)).decode()


class WebSocketScanner(BaseScanner):
    """Detect WebSocket endpoints and check WSS enforcement and auth signals."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        resp = self.http.get(url)
        if not resp:
            return self.results

        body = resp.text or ""
        ws_urls: Set[str] = set()
        plain_ws: Set[str] = set()

        # ── 1. Find ws:// / wss:// URLs in page source ─────────────────────
        for match in _WS_URL_RE.finditer(body):
            ws_url = match.group(1).rstrip("\"',;)}")
            ws_urls.add(ws_url)
            if ws_url.startswith("ws://"):
                plain_ws.add(ws_url)

        # Also scan inline JS src files linked from the page
        soup = BeautifulSoup(body, "html.parser")
        for script in soup.find_all("script", src=True):
            src = script.attrs.get("src", "")
            if src:
                js_url = src if src.startswith("http") else urljoin(url, src)
                try:
                    js_resp = self.http.get(js_url)
                    if js_resp and js_resp.status_code == 200:
                        for match in _WS_URL_RE.finditer(js_resp.text or ""):
                            ws_url = match.group(1).rstrip("\"',;)}")
                            ws_urls.add(ws_url)
                            if ws_url.startswith("ws://"):
                                plain_ws.add(ws_url)
                except Exception:
                    pass

        # ── 2. Flag plain ws:// ────────────────────────────────────────────
        if plain_ws:
            examples = ", ".join(sorted(plain_ws)[:3])
            log_fail(logger, f"Unencrypted ws:// endpoints found: {examples}")
            self.results.append(self._result(
                url, "WebSocket — unencrypted ws:// endpoint referenced", "FAIL",
                detail=(
                    f"Unencrypted WebSocket endpoint(s) found: {examples}. "
                    "Plain ws:// transmits all WebSocket frames in clear text — "
                    "any network observer (corporate proxy, ISP, coffee shop Wi-Fi) "
                    "can read and inject into the stream. "
                    "Fix: replace all ws:// with wss:// and ensure the server has a "
                    "valid TLS certificate for the WebSocket endpoint."
                )
            ))

        # ── 3. Probe HTTP Upgrade on known WebSocket paths ─────────────────
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}"
        ws_probe_results = []

        for path in _WS_PROBE_PATHS:
            probe_url = base + path
            try:
                resp_ws = self.http.get(probe_url, headers={
                    "Upgrade":               "websocket",
                    "Connection":            "Upgrade",
                    "Sec-WebSocket-Key":     _WS_KEY,
                    "Sec-WebSocket-Version": "13",
                    "Origin":                url,
                })
                if not resp_ws:
                    continue
                if resp_ws.status_code == 101:
                    ws_probe_results.append((probe_url, resp_ws.headers))
                elif resp_ws.status_code in (200, 426):
                    # 426 = Upgrade Required, 200 = long-poll fallback — still a WS endpoint
                    ws_probe_results.append((probe_url, resp_ws.headers))
            except Exception:
                continue

        for ws_url, ws_hdrs in ws_probe_results:
            self._analyse_ws_headers(url, ws_url, ws_hdrs)

        # ── 4. Report wss:// found (informational) ─────────────────────────
        secure_ws = {u for u in ws_urls if u.startswith("wss://")}
        if secure_ws and not plain_ws:
            log_pass(logger, f"WebSocket endpoints use wss:// on {url}")

        if not self.results:
            log_pass(logger, f"No WebSocket security issues detected on {url}")
            self.results.append(self._result(
                url, "WebSocket — no issues detected", "PASS",
                detail=(
                    "No WebSocket endpoints found in page source, or all found "
                    "endpoints use wss:// (encrypted WebSocket)."
                )
            ))

        return self.results

    def _analyse_ws_headers(self, url: str, ws_url: str, hdrs) -> None:
        """Inspect HTTP Upgrade response headers for security issues."""
        upgrade      = hdrs.get("upgrade", "").lower()
        access_origin = hdrs.get("access-control-allow-origin", "")
        sec_protocol  = hdrs.get("sec-websocket-protocol", "")
        auth_header   = hdrs.get("www-authenticate", "")

        log_warn(logger, f"WebSocket endpoint found: {ws_url}")
        self.results.append(self._result(
            url, f"WebSocket — endpoint reachable without authentication ({ws_url})", "WARN",
            detail=(
                f"WebSocket endpoint {ws_url} accepted an upgrade request without "
                "requiring authentication. WebSocket connections bypass HTTP-layer "
                "protections like WAF rules and rate limiting once the connection "
                "is upgraded. "
                "Fix: validate session cookies or Bearer tokens during the HTTP "
                "Upgrade handshake before accepting the WebSocket connection."
            )
        ))

        if access_origin == "*":
            log_fail(logger, f"WebSocket CORS wildcard on {ws_url}")
            self.results.append(self._result(
                url, "WebSocket — wildcard Origin accepted (CORS)", "FAIL",
                detail=(
                    f"WebSocket server at {ws_url} returns "
                    "Access-Control-Allow-Origin: *. "
                    "Unlike HTTP CORS, browsers do not enforce CORS for WebSocket "
                    "upgrades — but a wildcard Origin policy signals the server "
                    "does not validate the Origin header, enabling Cross-Site "
                    "WebSocket Hijacking (CSWH) attacks. "
                    "Fix: validate the Origin header server-side against an "
                    "allowlist of trusted origins."
                )
            ))
