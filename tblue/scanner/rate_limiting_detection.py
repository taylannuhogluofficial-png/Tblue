"""Rate limiting detection — missing rate-limit headers, no 429 on rapid requests, Retry-After absent."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-rate-limit-limit",
    "ratelimit-limit",
    "retry-after",
]

_AUTH_PATHS = [
    "/login", "/signin", "/auth/login", "/api/auth/login",
    "/api/login", "/account/login", "/user/login",
]

_PASSWORD_RESET_PATHS = [
    "/forgot-password", "/reset-password", "/api/forgot-password",
]

_RATE_LIMIT_PROBE_COUNT = 5  # send N rapid requests, check for 429


def _check_rate_limit_headers_present(headers: dict, url: str) -> list:
    findings = []
    found = [h for h in _RATE_LIMIT_HEADERS if h in {k.lower() for k in headers}]
    if not found:
        findings.append({
            "type": "rate_limiting_no_headers",
            "status": "WARN",
            "url": url,
            "detail": "No rate-limiting headers (X-RateLimit-*, Retry-After) in response — "
                      "cannot verify rate limiting is enforced",
        })
    return findings


def _check_auth_endpoint_rate_limited(http, origin: str) -> list:
    """Send rapid requests to auth endpoint and check if 429 is returned."""
    findings = []
    for path in _AUTH_PATHS[:3]:
        url = origin + path
        try:
            statuses = []
            for _ in range(_RATE_LIMIT_PROBE_COUNT):
                r = http.get(url)
                if r:
                    statuses.append(r.status_code)
                    if r.status_code == 429:
                        return []  # rate limiting works
                    if r.status_code not in (200, 400, 401, 403, 405, 422):
                        break  # not an auth endpoint

            if statuses and all(s not in (429, 403) for s in statuses):
                if statuses[0] in (200, 400, 401, 405, 422):
                    findings.append({
                        "type": "rate_limiting_auth_endpoint_unrestricted",
                        "status": "FAIL",
                        "url": url,
                        "detail": f"Auth endpoint {path} returned {statuses[0]} for {_RATE_LIMIT_PROBE_COUNT} "
                                  f"rapid requests without 429 — brute-force / credential stuffing risk",
                    })
                    return findings
        except Exception:
            pass
    return findings


class RateLimitingDetectionScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "rate_limiting_no_response", "PASS", detail="No response")]

        headers = dict(resp.headers) if resp.headers else {}
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for f in _check_rate_limit_headers_present(headers, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        for f in _check_auth_endpoint_rate_limited(self.http, origin):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "rate_limiting_ok", "PASS",
                                        detail="Rate limiting indicators present"))
        return results
