"""
Server-Sent Events (SSE) Security Scanner.

Server-Sent Events (EventSource API) is a W3C standard for push notifications
from server to browser. Unlike WebSockets, SSE uses plain HTTP and is often
overlooked in security reviews.

Common SSE security issues:

  1. Missing authentication — /events or /stream endpoints accessible without login
  2. CORS misconfiguration — EventSource follows CORS rules; a wildcard Access-Control
     header on an SSE endpoint can allow cross-origin eavesdropping
  3. Missing Content-Type: text/event-stream — some CDNs will buffer or transform
     the response if the content type is wrong, breaking the stream
  4. Cache-Control missing — SSE streams should never be cached (no-store)
  5. EventSource over HTTP (not HTTPS) — SSE streams are typically long-lived;
     a plaintext stream exposes all events to passive eavesdropping
  6. Reconnection interval too short — a default retry: <1000ms can enable
     DoS by getting all browsers to reconnect simultaneously

This scanner probes common SSE endpoint paths and analyzes their security headers.
It does NOT actually subscribe to or read the stream content (would be intrusive).

CWE-306: Missing Authentication for Critical Function
CWE-942: Permissive Cross-domain Policy with Untrusted Domains
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Common SSE endpoint paths
_SSE_PATHS = [
    "/events", "/stream", "/sse", "/api/events", "/api/stream",
    "/api/sse", "/realtime", "/push", "/live", "/subscribe",
    "/notifications", "/api/notifications", "/ws/events",
    "/v1/events", "/v2/events",
]

_TEXT_EVENT_STREAM = "text/event-stream"


class SSESecurityScanner(BaseScanner):
    """Detects Server-Sent Event endpoints and audits their security configuration."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        base = url.rstrip("/")
        sse_endpoints: List[str] = []

        # 1. Discover SSE endpoints by probing paths
        for path in _SSE_PATHS:
            probe_url = base + path
            resp = self.http.get(probe_url)
            if resp is None:
                continue

            ct = (resp.headers or {}).get("content-type", "") or ""
            if _TEXT_EVENT_STREAM in ct.lower():
                sse_endpoints.append(probe_url)
                logger.info(f"SSE Security: found endpoint at {probe_url}")

        # 2. Also check if the page source references EventSource
        resp0 = self.http.get(url)
        if resp0 is not None:
            body = (resp0.text or "")[:100_000]
            if "EventSource" in body or "text/event-stream" in body:
                eventsource_urls = re.findall(
                    r"""new\s+EventSource\s*\(\s*["']([^"']+)["']""", body, re.I
                )
                for eu in eventsource_urls:
                    if not eu.startswith("http"):
                        from urllib.parse import urljoin
                        eu = urljoin(url, eu)
                    if eu not in sse_endpoints:
                        sse_endpoints.append(eu)
                        logger.info(f"SSE Security: EventSource reference found: {eu}")

        if not sse_endpoints:
            log_pass(logger, f"SSE Security — no Server-Sent Events endpoints detected on {url}")
            self.results.append(self._result(
                url, "SSE Security — no EventSource/SSE endpoints detected", "PASS",
                detail="No Server-Sent Events endpoints were found. Checked "
                       f"{len(_SSE_PATHS)} common paths and scanned page source "
                       "for EventSource constructor calls."))
            return self.results

        for sse_url in sse_endpoints[:5]:
            self._audit_sse_endpoint(url, sse_url)

        return self.results

    def _audit_sse_endpoint(self, page_url: str, sse_url: str) -> None:
        resp = self.http.get(sse_url)
        if resp is None:
            return

        headers = resp.headers or {}
        status = resp.status_code
        ct = headers.get("content-type", "") or ""
        cc = headers.get("cache-control", "") or ""
        acao = headers.get("access-control-allow-origin", "") or ""
        parsed = urlparse(sse_url)

        # No authentication check — is the endpoint accessible without cookies/tokens?
        if status in (200, 206) and _TEXT_EVENT_STREAM in ct.lower():
            # Check if it's HTTP (not HTTPS)
            if parsed.scheme == "http":
                log_fail(logger, f"SSE Security — SSE endpoint over plaintext HTTP: {sse_url}")
                self.results.append(self._result(
                    page_url,
                    f"SSE Security — EventSource endpoint over HTTP (unencrypted stream)",
                    "FAIL",
                    detail=(
                        f"Server-Sent Events endpoint is accessible over HTTP:\n  {sse_url}\n\n"
                        f"SSE streams are typically long-lived connections. A plaintext stream "
                        f"exposes ALL pushed events to passive network eavesdropping. "
                        f"An adversary on the network can read every notification pushed to "
                        f"every connected user.\n\n"
                        f"Fix: Force HTTPS for all SSE endpoints (redirect HTTP to HTTPS)."
                    ),
                ))

            # No authentication required (reached 200 without session cookies)
            log_warn(logger, f"SSE Security — SSE endpoint accessible without authentication: {sse_url}")
            self.results.append(self._result(
                page_url,
                f"SSE Security — EventSource endpoint accessible without authentication",
                "WARN",
                detail=(
                    f"The SSE endpoint at {sse_url} returned HTTP {status} without "
                    f"any session cookie or authentication token. If this endpoint "
                    f"delivers user-specific events, it should require authentication.\n\n"
                    f"Fix: Verify the endpoint requires a valid session. If it serves "
                    f"public broadcast events, this is acceptable."
                ),
            ))

            # Check CORS on SSE endpoint
            if acao == "*":
                log_fail(logger, f"SSE Security — wildcard CORS on SSE endpoint: {sse_url}")
                self.results.append(self._result(
                    page_url,
                    "SSE Security — SSE endpoint has Access-Control-Allow-Origin: *",
                    "FAIL",
                    detail=(
                        f"The SSE endpoint {sse_url} allows any origin to subscribe:\n"
                        f"  Access-Control-Allow-Origin: *\n\n"
                        f"With a wildcard CORS policy, any website can create an EventSource "
                        f"pointing to this endpoint and receive all push events, even if they "
                        f"contain user-specific data.\n\n"
                        f"Fix: Replace '*' with the specific origin(s) that should have access, "
                        f"e.g., Access-Control-Allow-Origin: https://yourapp.com"
                    ),
                ))
            elif acao and acao not in ("", "null"):
                # Specific origin — probably fine, just note it
                log_pass(logger, f"SSE Security — SSE CORS restricted to: {acao}")
                self.results.append(self._result(
                    page_url,
                    f"SSE Security — SSE CORS configured for specific origin ({acao[:50]})",
                    "PASS",
                    detail=f"SSE endpoint at {sse_url} restricts CORS to: {acao}"
                ))

            # Cache-Control on SSE
            if not cc or "no-store" not in cc.lower():
                log_warn(logger, f"SSE Security — SSE endpoint missing no-store Cache-Control: {sse_url}")
                self.results.append(self._result(
                    page_url,
                    "SSE Security — SSE endpoint missing Cache-Control: no-store",
                    "WARN",
                    detail=(
                        f"Cache-Control: {cc or '(none)'}\n\n"
                        f"Server-Sent Events streams should always include "
                        f"'Cache-Control: no-store' to prevent any proxy or CDN "
                        f"from caching event stream responses."
                    ),
                ))

        elif status == 401 or status == 403:
            log_pass(logger, f"SSE Security — SSE endpoint requires authentication: {sse_url}")
            self.results.append(self._result(
                page_url,
                f"SSE Security — EventSource endpoint requires authentication (HTTP {status})",
                "PASS",
                detail=f"SSE endpoint at {sse_url} correctly returns HTTP {status} "
                       f"for unauthenticated requests.",
            ))
