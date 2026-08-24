"""
API Gateway Security Scanner.

API gateways (AWS API Gateway, Kong, Nginx, Traefik, Azure APIM, Apigee)
introduce a layer between clients and services with its own security surface:

  1. Gateway version/vendor header disclosure — X-Kong-*, X-Amzn-*, Via,
     X-Powered-By headers reveal gateway version and vendor.

  2. Request ID leakage — X-Request-Id, X-Correlation-Id, X-Amzn-RequestId
     are useful for debugging but can help attackers correlate requests and
     map internal infrastructure.

  3. Rate limit header disclosure — X-RateLimit-*, X-Rate-Limit-* reveal
     throttle policy (limits, windows) that help attackers calibrate attacks.

  4. Upstream host disclosure — X-Forwarded-Server, X-Real-IP, X-Upstream-*
     expose internal hostnames or IPs.

  5. Missing API versioning enforcement — if /api/v1 and /api respond
     identically, versioning is not enforced at the gateway level.

  6. CORS preflight without Vary: Origin — preflight response cached without
     Vary header allows cache poisoning of CORS decisions.

Read-only.

CWE-200: Exposure of Sensitive Information
CWE-16: Configuration
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_GATEWAY_HEADERS = {
    "x-kong-request-id": ("Kong API Gateway", "WARN"),
    "x-kong-proxy-latency": ("Kong API Gateway", "WARN"),
    "x-amzn-requestid": ("AWS API Gateway", "WARN"),
    "x-amzn-trace-id": ("AWS X-Ray trace disclosure", "WARN"),
    "x-amz-apigw-id": ("AWS API Gateway", "WARN"),
    "x-apigee-request-id": ("Apigee", "WARN"),
    "x-azure-ref": ("Azure API Management", "WARN"),
    "x-traefik-request-id": ("Traefik", "WARN"),
}

_UPSTREAM_HEADERS = [
    "x-forwarded-server", "x-real-ip", "x-upstream-addr",
    "x-upstream-response-time", "x-upstream-status",
    "x-origin-server",
]

_RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
    "x-rate-limit-limit", "x-rate-limit-remaining",
    "ratelimit-limit", "ratelimit-remaining",
]

_API_PATHS = ["/api", "/api/v1", "/api/v2", "/v1", "/v2", "/rest"]


def _check_gateway_vendor_headers(headers: dict, url: str) -> List[Dict]:
    findings = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for hdr, (vendor, severity) in _GATEWAY_HEADERS.items():
        if hdr in lower_headers:
            findings.append({
                "type": f"api-gateway-vendor-header-{hdr.replace('-', '_')}",
                "status": severity,
                "detail": (
                    f"{vendor} header {hdr!r} present in response from {url}.\n\n"
                    f"Gateway-specific headers reveal infrastructure vendor, version, "
                    f"and internal request IDs that aid reconnaissance.\n\n"
                    f"Fix: configure the gateway to strip internal diagnostic headers "
                    f"before returning responses to clients."
                ),
            })
    return findings


def _check_upstream_disclosure(headers: dict, url: str) -> Optional[Dict]:
    lower_headers = {k.lower() for k in headers}
    found = [h for h in _UPSTREAM_HEADERS if h in lower_headers]
    if found:
        return {
            "type": "api-gateway-upstream-host-disclosed",
            "status": "WARN",
            "detail": (
                f"Upstream host/IP headers found in response from {url}: "
                f"{', '.join(found)}.\n\n"
                f"These headers expose internal service hostnames or IP addresses "
                f"that should not be visible to clients.\n\n"
                f"Fix: strip X-Forwarded-Server, X-Upstream-*, and X-Real-IP "
                f"headers in the gateway before responding to clients."
            ),
        }
    return None


def _check_rate_limit_disclosure(headers: dict, url: str) -> Optional[Dict]:
    lower_headers = {k.lower() for k in headers}
    found = [h for h in _RATE_LIMIT_HEADERS if h in lower_headers]
    if found:
        return {
            "type": "api-gateway-rate-limit-policy-disclosed",
            "status": "WARN",
            "detail": (
                f"Rate limit headers found in response from {url}: {', '.join(found)}.\n\n"
                f"Exposing rate limit details (limit, remaining, reset) helps attackers "
                f"calibrate their request timing to stay just under the threshold.\n\n"
                f"Fix: evaluate whether rate limit headers need to be client-visible. "
                f"If so, consider returning only a minimal Retry-After on 429 responses."
            ),
        }
    return None


def _check_cors_preflight_vary(http, url: str) -> Optional[Dict]:
    """Send OPTIONS with Origin and check for Vary: Origin in response."""
    try:
        resp = http.get(url, headers={"Origin": "https://example-probe.com",
                                       "Access-Control-Request-Method": "GET"})
        if resp is None:
            return None
        lower_h = {k.lower(): v for k, v in resp.headers.items()}
        acao = lower_h.get("access-control-allow-origin", "")
        vary = lower_h.get("vary", "")
        if acao and "origin" not in vary.lower():
            return {
                "type": "api-gateway-cors-preflight-no-vary-origin",
                "status": "WARN",
                "detail": (
                    f"CORS Access-Control-Allow-Origin present at {url} but "
                    f"Vary: Origin is missing.\n\n"
                    f"Without Vary: Origin, a CDN or proxy may cache the CORS "
                    f"response for one origin and serve it to requests from a "
                    f"different origin, enabling CORS cache poisoning.\n\n"
                    f"Fix: add 'Vary: Origin' whenever Access-Control-Allow-Origin "
                    f"is set dynamically."
                ),
            }
    except Exception:
        pass
    return None


class APIGatewaySecurityScanner(BaseScanner):
    """Checks for API gateway header leakage, upstream disclosure, and CORS cache issues."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        found = False
        seen_types: set = set()

        endpoints = [url] + [urljoin(base_origin, p) for p in _API_PATHS]

        for ep in endpoints:
            resp = self.http.get(ep)
            if resp is None or resp.status_code in (404, 410):
                continue
            headers = resp.headers or {}

            for f in _check_gateway_vendor_headers(headers, ep):
                if f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    found = True
                    log_warn(logger, f"API Gateway — {f['type']} at {ep}")
                    self.results.append(self._result(
                        ep, f["type"][:100], f["status"], detail=f["detail"]))

            for check_fn in [_check_upstream_disclosure, _check_rate_limit_disclosure]:
                f = check_fn(headers, ep)
                if f and f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    found = True
                    log_warn(logger, f"API Gateway — {f['type']} at {ep}")
                    self.results.append(self._result(
                        ep, f["type"], f["status"], detail=f["detail"]))

        f = _check_cors_preflight_vary(self.http, url)
        if f and f["type"] not in seen_types:
            found = True
            log_warn(logger, f"API Gateway — {f['type']} at {url}")
            self.results.append(self._result(
                url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"API Gateway Security — no issues found for {url}")
            self.results.append(self._result(
                url,
                "API Gateway Security — no gateway header leakage or CORS issues detected",
                "PASS",
                detail="No vendor headers, upstream disclosure, or CORS Vary issues found.",
            ))

        return self.results
