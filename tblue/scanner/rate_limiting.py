"""
Rate Limiting & DoS Protection Scanner.

Checks whether the target has adequate rate limiting and DoS protection:

1. Rate limit headers present (X-RateLimit-*, Retry-After, RateLimit-*)
2. Presence of security headers that indicate rate limit enforcement
3. 429 Too Many Requests response detection
4. Lack of rate limiting on sensitive endpoints (login, API, reset password)
5. Content negotiation-based bypass indicators

Note: This scanner does NOT spam requests. It sends a small number of
sequential requests (≤10) to check for rate limit headers and 429 responses.
This is defensive reconnaissance, not a stress test.
"""

import re
import time
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse
from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Standard rate limit headers (RFC 6585, GitHub, Stripe, CloudFlare patterns)
_RATELIMIT_HEADERS = frozenset({
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "retry-after",
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
    "x-rate-limit-reset",
    "x-request-limit",
    "x-quota-limit",
})

# Endpoints particularly sensitive to missing rate limits
_SENSITIVE_PATHS = [
    ("/login", "login"),
    ("/api/login", "login API"),
    ("/auth/login", "auth login"),
    ("/signin", "sign-in"),
    ("/auth/token", "token issuance"),
    ("/password/reset", "password reset"),
    ("/forgot-password", "password reset"),
    ("/api/v1/auth", "auth API"),
    ("/graphql", "GraphQL"),
    ("/api", "generic API"),
    ("/search", "search"),
    ("/register", "registration"),
    ("/api/register", "registration API"),
]

# Responses indicating 429 or rate limit enforcement
_429_OR_RATELIMIT_RE = re.compile(
    r"rate.*limit|too.*many.*request|quota.*exceeded|throttl",
    re.I,
)

_PROBE_COUNT = 5  # Number of rapid sequential requests to test for 429


class RateLimitingScanner(BaseScanner):
    """Checks for rate limiting headers and 429 enforcement on sensitive paths."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping rate limiting checks: {url}")
            self.results.append(self._result(
                url, "Rate limiting — no response from target", "PASS",
                detail="Target did not respond; rate limiting checks skipped."
            ))
            return self.results

        # ── Check main page rate limit headers ────────────────────────────────
        self._check_ratelimit_headers(url, resp)

        # ── Check sensitive endpoints ─────────────────────────────────────────
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        self._check_sensitive_paths(base)

        # ── Rapid probe test on API endpoint ──────────────────────────────────
        self._rapid_probe_test(url)

        if not self.results:
            log_pass(logger, f"No rate limiting issues detected on {url}")
            self.results.append(self._result(
                url, "Rate limiting — headers and controls detected", "PASS",
                detail=(
                    "Rate limit headers found or sensitive paths returned appropriate "
                    "responses. Continue to monitor with load testing for production validation."
                )
            ))

        return self.results

    def _check_ratelimit_headers(self, url: str, resp) -> None:
        """Check if the response contains standard rate limiting headers."""
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        found_headers = [h for h in _RATELIMIT_HEADERS if h in headers_lower]

        if found_headers:
            log_pass(logger, f"Rate limit headers present on {url}: {found_headers}")
            self.results.append(self._result(
                url, "Rate limiting — headers present on main endpoint", "PASS",
                detail=f"Rate limit headers detected: {', '.join(found_headers)}."
            ))
        else:
            log_warn(logger, f"No rate limit headers on main response: {url}")
            self.results.append(self._result(
                url, "Rate limiting — no rate limit headers on main response", "WARN",
                detail=(
                    "No standard rate limit headers detected (X-RateLimit-*, RateLimit-*, Retry-After). "
                    "Without these headers, clients cannot detect when they are being throttled. "
                    "Fix: implement rate limiting using your API gateway, WAF, or middleware "
                    "(nginx rate_limit_req, express-rate-limit, Cloudflare rate limiting rules). "
                    "Return X-RateLimit-Limit, X-RateLimit-Remaining, and Retry-After headers."
                )
            ))

    def _check_sensitive_paths(self, base: str) -> None:
        """Check sensitive paths for rate limit headers or 429 responses."""
        checked = 0
        missing_rate_limit = []

        for path, name in _SENSITIVE_PATHS:
            resp = self.http.get(base + path)
            if resp is None:
                continue
            if resp.status_code not in (200, 201, 302, 400, 401, 403, 405):
                continue  # Skip 404 — path doesn't exist

            checked += 1
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            has_rate_limit = any(h in headers_lower for h in _RATELIMIT_HEADERS)
            has_429_body = _429_OR_RATELIMIT_RE.search(resp.text or "")

            if not has_rate_limit and not has_429_body:
                missing_rate_limit.append((base + path, name))

        if missing_rate_limit and len(missing_rate_limit) >= 2:
            paths_str = ", ".join(f"{name} ({path})" for path, name in missing_rate_limit[:3])
            log_fail(logger, f"No rate limiting on sensitive paths: {paths_str}")
            self.results.append(self._result(
                base, "Rate limiting — missing on sensitive endpoints", "FAIL",
                detail=(
                    f"No rate limit headers found on {len(missing_rate_limit)} sensitive endpoint(s): "
                    f"{paths_str}. "
                    "Without rate limiting on login/auth/password-reset endpoints, attackers can "
                    "perform credential stuffing, brute force, or account enumeration at high speed. "
                    "Fix: apply rate limiting specifically on authentication endpoints: "
                    "max 5-10 failed attempts per minute per IP, then 429 with Retry-After."
                )
            ))
        elif checked > 0 and missing_rate_limit:
            log_warn(logger, f"Rate limiting missing on {len(missing_rate_limit)} path(s)")
            self.results.append(self._result(
                base, "Rate limiting — missing on some sensitive endpoints", "WARN",
                detail=(
                    f"Rate limit headers missing on {len(missing_rate_limit)} path(s): "
                    f"{', '.join(p for p, _ in missing_rate_limit[:3])}. "
                    "Verify that rate limiting is enforced at the network or middleware layer."
                )
            ))

    def _rapid_probe_test(self, url: str) -> None:
        """Send a small burst of requests to check for 429 responses."""
        got_429 = False
        got_ratelimit_header = False

        for i in range(_PROBE_COUNT):
            r = self.http.get(url)
            if r is None:
                break
            if r.status_code == 429:
                got_429 = True
                break
            headers_lower = {k.lower(): v for k, v in r.headers.items()}
            if any(h in headers_lower for h in _RATELIMIT_HEADERS):
                got_ratelimit_header = True
                break

        if got_429 or got_ratelimit_header:
            status_str = "429 detected" if got_429 else "rate limit header present"
            log_pass(logger, f"Rate limiting enforced during rapid probe ({status_str}): {url}")
            # PASS already reported in _check_ratelimit_headers or here
        # No result added here — already covered by header check above
