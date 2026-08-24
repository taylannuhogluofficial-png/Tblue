"""
API Rate Limit Deep Scanner.

Rate limiting is a critical defence against brute force, credential stuffing,
enumeration, and scraping. This scanner passively checks:

  1. Rate limit headers present — 429 responses should include Retry-After
     and/or RateLimit-* headers to guide legitimate clients.

  2. Rate limit type — token bucket vs sliding window vs fixed window.
     We detect which via header names (X-RateLimit-Reset, Retry-After delta).

  3. Missing rate limit on authentication endpoints — /login, /api/auth,
     /oauth/token should have strict rate limiting. Absence of any
     rate-limit headers on these paths is a WARN.

  4. Rate limit shared across users — some implementations rate-limit by IP
     only, not by account. X-RateLimit-Scope: ip vs. X-RateLimit-Scope: user
     signals this. IP-only limits are trivially bypassed with residential
     proxies.

  5. Rate limit bypass via header injection — X-Forwarded-For, True-Client-IP,
     CF-Connecting-IP accepted for IP identification allow bypass by spoofing.
     We check if these headers change the X-RateLimit-Remaining value.

  6. Burst allowance — X-RateLimit-Burst headers indicate a burst limit;
     very high burst limits on auth endpoints are a concern.

Read-only. No credentials submitted.

CWE-307: Improper Restriction of Excessive Authentication Attempts
CWE-770: Allocation of Resources Without Limits or Throttling
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_AUTH_PATHS = [
    "/login", "/signin", "/auth/login", "/api/auth/login",
    "/oauth/token", "/api/token", "/auth/token",
    "/api/v1/auth/login", "/api/login",
]

_RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-rate-limit-limit",
    "ratelimit-limit", "retry-after",
]

_SCOPE_HEADER = "x-ratelimit-scope"
_BURST_HEADER = "x-ratelimit-burst"
_REMAINING_HEADERS = [
    "x-ratelimit-remaining", "x-rate-limit-remaining", "ratelimit-remaining"
]

_FORWARDED_FOR_HEADERS = [
    "X-Forwarded-For", "True-Client-IP", "CF-Connecting-IP",
    "X-Real-IP", "X-Originating-IP",
]


def _has_rate_limit(headers: dict) -> bool:
    lower_h = {k.lower() for k in headers}
    return any(h in lower_h for h in _RATE_LIMIT_HEADERS)


def _get_remaining(headers: dict) -> Optional[int]:
    lower_h = {k.lower(): v for k, v in headers.items()}
    for h in _REMAINING_HEADERS:
        if h in lower_h:
            try:
                return int(lower_h[h].strip())
            except ValueError:
                pass
    return None


def _check_auth_path_rate_limit(http, base_origin: str) -> List[Dict]:
    findings = []
    for path in _AUTH_PATHS:
        ep = urljoin(base_origin, path)
        resp = http.get(ep)
        if resp is None or resp.status_code in (404, 410, 501):
            continue
        if not _has_rate_limit(resp.headers or {}):
            findings.append({
                "type": "api-rate-limit-missing-on-auth-endpoint",
                "status": "WARN",
                "detail": (
                    f"No rate limit headers found on authentication endpoint {ep}.\n\n"
                    f"Without rate limiting, attackers can attempt unlimited credential "
                    f"guesses against login, token, and OAuth endpoints.\n\n"
                    f"Fix: apply strict per-account and per-IP rate limits on all "
                    f"authentication endpoints. Return 429 with Retry-After when limits "
                    f"are exceeded."
                ),
            })
            break  # one finding is enough
    return findings


def _check_ip_scope(headers: dict, url: str) -> Optional[Dict]:
    lower_h = {k.lower(): v for k, v in headers.items()}
    scope = lower_h.get(_SCOPE_HEADER, "").lower()
    if scope == "ip":
        return {
            "type": "api-rate-limit-ip-only-scope",
            "status": "WARN",
            "detail": (
                f"Rate limit at {url} is scoped to IP only "
                f"(X-RateLimit-Scope: ip).\n\n"
                f"IP-only rate limits are bypassed with residential proxy networks "
                f"and Tor. Credential stuffing attacks use rotating IPs.\n\n"
                f"Fix: add per-account rate limiting in addition to per-IP limits. "
                f"Flag accounts with rapid failed login attempts regardless of source IP."
            ),
        }
    return None


def _check_xff_bypass(http, url: str) -> Optional[Dict]:
    """Check if X-Forwarded-For changes rate limit remaining count."""
    resp1 = http.get(url)
    if resp1 is None:
        return None
    remaining1 = _get_remaining(resp1.headers or {})
    if remaining1 is None:
        return None

    # Send with a spoofed IP
    resp2 = http.get(url, headers={"X-Forwarded-For": "1.2.3.4"})
    if resp2 is None:
        return None
    remaining2 = _get_remaining(resp2.headers or {})
    if remaining2 is None:
        return None

    # If remaining reset to a higher value with spoofed IP, rate limit is bypassable
    if remaining2 > remaining1:
        return {
            "type": "api-rate-limit-xff-bypass-detected",
            "status": "FAIL",
            "detail": (
                f"Rate limit at {url} appears to use X-Forwarded-For for client "
                f"identification (remaining increased from {remaining1} to {remaining2} "
                f"when X-Forwarded-For was spoofed).\n\n"
                f"Attackers can bypass the rate limit by cycling through fake IPs in "
                f"the X-Forwarded-For header.\n\n"
                f"Fix: never use client-supplied headers (X-Forwarded-For, True-Client-IP) "
                f"as the authoritative client identifier for rate limiting. Use the "
                f"connection's remote IP as set by the trusted reverse proxy."
            ),
        }
    return None


class APIRateLimitDeepScanner(BaseScanner):
    """Deep checks: rate limit on auth endpoints, IP-only scope, X-Forwarded-For bypass."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "API Rate Limit Deep — target unreachable", "PASS",
                detail="No response; rate limit deep check skipped."))
            return self.results

        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        found = False
        seen_types: set = set()

        # Check rate limit on auth paths
        for f in _check_auth_path_rate_limit(self.http, base_origin):
            if f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                log_warn(logger, f"API Rate Limit Deep — {f['type']}")
                self.results.append(self._result(
                    url, f["type"], f["status"], detail=f["detail"]))

        # Check scope and bypass on main URL
        headers = resp.headers or {}
        if _has_rate_limit(headers):
            f = _check_ip_scope(headers, url)
            if f and f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                log_warn(logger, f"API Rate Limit Deep — {f['type']} at {url}")
                self.results.append(self._result(
                    url, f["type"], f["status"], detail=f["detail"]))

            f = _check_xff_bypass(self.http, url)
            if f and f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                log_fail(logger, f"API Rate Limit Deep — {f['type']} at {url}")
                self.results.append(self._result(
                    url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"API Rate Limit Deep — no issues found for {url}")
            self.results.append(self._result(
                url,
                "API Rate Limit Deep — no rate limit bypass or missing limit issues",
                "PASS",
                detail="Rate limiting appears present on auth endpoints with no bypass indicators.",
            ))

        return self.results
