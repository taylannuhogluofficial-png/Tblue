"""Server-Sent Events (SSE) security — missing auth on event streams, CORS misconfiguration, data leakage."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_SSE_PATHS = [
    "/events", "/sse", "/stream", "/api/events", "/api/stream",
    "/api/v1/events", "/api/v1/stream", "/notifications", "/updates",
    "/live", "/push", "/api/notifications", "/api/live",
]

_SSE_CONTENT_TYPE_RE = re.compile(r'text/event-stream', re.I)
_SSE_DATA_RE = re.compile(r'^data\s*:', re.M)
_SSE_ID_RE = re.compile(r'^id\s*:', re.M)
_SSE_EVENT_RE = re.compile(r'^event\s*:', re.M)

_SENSITIVE_SSE_DATA_RE = re.compile(
    r'data:\s*\{[^}]*(?:"(?:email|token|password|api_key|secret|session|user_id|credit)")',
    re.I,
)

_RETRY_INFINITE_RE = re.compile(r'retry\s*:\s*(?:0|1|2|3|4|5)\b', re.I)


def _get_header(headers, name: str) -> str:
    if hasattr(headers, "get"):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    if isinstance(headers, dict):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    return ""


def _check_sse_endpoint(http, url: str) -> list:
    findings = []
    try:
        resp = http.get(url)
        if resp is None:
            return findings

        ct = _get_header(resp.headers, "content-type")
        body = resp.text or ""

        if not (_SSE_CONTENT_TYPE_RE.search(ct) or _SSE_DATA_RE.search(body)):
            return findings

        if resp.status_code == 200:
            acao = _get_header(resp.headers, "access-control-allow-origin")
            if acao == "*":
                findings.append({
                    "type": "sse_cors_wildcard",
                    "status": "FAIL",
                    "url": url,
                    "detail": (f"SSE endpoint at {url} has Access-Control-Allow-Origin: * — "
                               f"any origin can subscribe to this event stream, "
                               f"potentially receiving sensitive real-time data"),
                })

            cache = _get_header(resp.headers, "cache-control")
            if "no-store" not in cache.lower() and "no-cache" not in cache.lower():
                findings.append({
                    "type": "sse_cacheable_stream",
                    "status": "WARN",
                    "url": url,
                    "detail": (f"SSE endpoint at {url} lacks Cache-Control: no-store — "
                               f"event stream responses may be cached by proxies, "
                               f"replaying stale events to wrong users"),
                })

            if _SENSITIVE_SSE_DATA_RE.search(body):
                findings.append({
                    "type": "sse_sensitive_data_in_stream",
                    "status": "FAIL",
                    "url": url,
                    "detail": f"SSE stream at {url} contains sensitive fields (email/token/session) in event data",
                })

    except Exception:
        pass
    return findings


class ServerSentEventsSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "sse_no_response", "PASS",
                                 detail="No response")]

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        sse_found = False
        for path in _SSE_PATHS:
            for f in _check_sse_endpoint(self.http, origin + path):
                sse_found = True
                results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))
            if sse_found and results:
                break

        if not results:
            if sse_found:
                results.append(self._result(url, "sse_found_no_issues", "PASS",
                                            detail="SSE endpoint found but no security issues detected"))
            else:
                results.append(self._result(url, "sse_not_found", "PASS",
                                            detail="No Server-Sent Events endpoints found at common paths"))
        return results
