"""API Rate Limit Headers scanner — passive detection of missing or misconfigured rate-limit response headers."""
import re
from .base import BaseScanner

_RL_ANY_RE = re.compile(
    r'(?:x-ratelimit|ratelimit|retry-after|x-rate-limit|x-request-limit)',
    re.I,
)

_RL_PRESENT_RE = re.compile(
    r'(?:x-ratelimit-limit|x-ratelimit-remaining|x-ratelimit-reset|'
    r'ratelimit-limit|ratelimit-remaining|ratelimit-reset|'
    r'x-rate-limit-limit|x-rate-limit-remaining)',
    re.I,
)

_RL_RETRY_AFTER_RE = re.compile(r'retry-after\s*:\s*(\d+)', re.I)

_RL_UNLIMITED_RE = re.compile(
    r'(?:x-ratelimit-limit|ratelimit-limit)\s*:\s*0\b',
    re.I,
)

_RL_INCONSISTENT_RE = re.compile(
    r'x-ratelimit-limit\s*:\s*(\d+).*?x-rate-limit-limit\s*:\s*(\d+)',
    re.I | re.S,
)

_API_ENDPOINT_RE = re.compile(
    r'(?:/api/|/v\d+/|/graphql|/rest/|application/json)',
    re.I,
)


class APIRateLimitHeadersScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "api_rate_limit_headers_not_used", "PASS")]

        headers_str = ' '.join(f'{k}: {v}' for k, v in resp.headers.items())
        body = resp.text

        if not (_RL_ANY_RE.search(headers_str) or _API_ENDPOINT_RE.search(url) or _API_ENDPOINT_RE.search(body)):
            return [self._result(url, "api_rate_limit_headers_not_used", "PASS")]

        findings = []

        if _API_ENDPOINT_RE.search(url) and not _RL_PRESENT_RE.search(headers_str):
            findings.append(self._result(
                url, "api_rate_limit_headers_missing", "WARN",
                detail="API endpoint detected but no RateLimit/X-RateLimit response headers found — clients and intermediaries cannot observe throttle state; brute-force and enumeration attacks are unsignalled.",
            ))

        if _RL_UNLIMITED_RE.search(headers_str):
            findings.append(self._result(
                url, "api_rate_limit_zero_limit", "FAIL",
                detail="RateLimit-Limit or X-RateLimit-Limit header value is 0 — advertises unlimited requests per window; effectively disables rate limiting for compliant clients.",
            ))

        m = _RL_RETRY_AFTER_RE.search(headers_str)
        if m and int(m.group(1)) < 1:
            findings.append(self._result(
                url, "api_rate_limit_retry_after_zero", "WARN",
                detail="Retry-After header is 0 — tells clients to retry immediately after being rate-limited; provides no backoff delay and allows rapid re-attempts.",
            ))

        if _RL_INCONSISTENT_RE.search(headers_str):
            findings.append(self._result(
                url, "api_rate_limit_inconsistent_headers", "WARN",
                detail="Both X-RateLimit-Limit and X-Rate-Limit-Limit present with different namespaces — proxy/CDN and origin may apply conflicting limits causing unpredictable throttling.",
            ))

        return findings or [self._result(url, "api_rate_limit_headers_safe", "PASS")]
