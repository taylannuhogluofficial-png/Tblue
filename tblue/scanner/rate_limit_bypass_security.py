"""Rate Limit Bypass security scanner — passive detection of rate limit bypass patterns."""
import re
from .base import BaseScanner

_RLB_ANY_RE = re.compile(
    r'(?:X-Forwarded-For\b|X-Real-IP\b|'
    r'rateLimit\b|rateLimiter\b|throttle\b|'
    r'maxAttempts\b|loginAttempts\b|'
    r'retryAfter\b|Retry-After\b)',
    re.I,
)

_RLB_IP_HEADER_FROM_PARAM_RE = re.compile(
    r'(?:X-Forwarded-For|X-Real-IP)\b[^;]{0,300}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_RLB_ATTEMPT_COUNTER_CLIENT_RE = re.compile(
    r'(?:loginAttempts|maxAttempts|retryCount)\b[^;]{0,300}'
    r'(?:localStorage|sessionStorage|cookie)',
    re.I,
)

_RLB_BYPASS_HEADER_SET_RE = re.compile(
    r'headers\s*:\s*\{[^}]{0,300}'
    r'["\']X-Forwarded-For["\'][^}]{0,200}'
    r'(?:searchParams|location\.hash|location\.href|userInput)',
    re.I,
)

_RLB_RATE_FROM_PARAM_RE = re.compile(
    r'(?:rateLimit|throttle|maxAttempts)\b[^;]{0,300}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class RateLimitBypassSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "rate_limit_bypass_not_used", "PASS")]

        body = resp.text

        if not _RLB_ANY_RE.search(body):
            return [self._result(url, "rate_limit_bypass_not_used", "PASS")]

        findings = []

        if _RLB_IP_HEADER_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "rate_limit_bypass_ip_header_param", "FAIL",
                detail="X-Forwarded-For/X-Real-IP header value from URL parameter — attacker-controlled IP header value enables rate limit bypass by spoofing source IP.",
            ))

        if _RLB_ATTEMPT_COUNTER_CLIENT_RE.search(body):
            findings.append(self._result(
                url, "rate_limit_bypass_client_counter", "FAIL",
                detail="loginAttempts/maxAttempts/retryCount stored in localStorage/sessionStorage/cookie — client-side rate limit counter is trivially bypassed by clearing storage.",
            ))

        if _RLB_BYPASS_HEADER_SET_RE.search(body):
            findings.append(self._result(
                url, "rate_limit_bypass_header_injection", "FAIL",
                detail="X-Forwarded-For header set from URL parameter in fetch request — client injects its own IP header to spoof source and bypass server-side rate limiting.",
            ))

        if _RLB_RATE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "rate_limit_config_from_param", "WARN",
                detail="rateLimit/throttle/maxAttempts value from URL parameter — attacker-controlled rate limit configuration enables bypass by setting high thresholds.",
            ))

        return findings or [self._result(url, "rate_limit_bypass_safe", "PASS")]
