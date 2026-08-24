"""Token Refresh security scanner — passive detection of insecure token refresh patterns."""
import re
from .base import BaseScanner

_TR_ANY_RE = re.compile(
    r'(?:refresh.?token\b|refreshToken\b|'
    r'access.?token\b|accessToken\b|'
    r'token.?refresh\b|renewToken\b|'
    r'expires.?in\b|expiresAt\b)',
    re.I,
)

_TR_FROM_PARAM_RE = re.compile(
    r'(?:refreshToken|refresh.?token)\b[^;]{0,300}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_TR_PLAINTEXT_STORAGE_RE = re.compile(
    r'(?:localStorage|sessionStorage)\.setItem\s*\(\s*["\']'
    r'(?:refresh.?token|refreshToken|access.?token)["\']',
    re.I,
)

_TR_TOKEN_EXFIL_RE = re.compile(
    r'(?:refreshToken|refresh.?token)\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_TR_LOGGED_RE = re.compile(
    r'(?:refreshToken|access.?token|accessToken)\b[^;]{0,300}'
    r'(?:console\.log|console\.warn|console\.error)',
    re.I,
)


class TokenRefreshSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "token_refresh_not_used", "PASS")]

        body = resp.text

        if not _TR_ANY_RE.search(body):
            return [self._result(url, "token_refresh_not_used", "PASS")]

        findings = []

        if _TR_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "token_refresh_from_param", "FAIL",
                detail="Refresh token read from URL parameter — refresh tokens in URLs are logged in access logs and browser history (token leakage enabling persistent account takeover).",
            ))

        if _TR_PLAINTEXT_STORAGE_RE.search(body):
            findings.append(self._result(
                url, "token_refresh_plaintext_storage", "WARN",
                detail="Refresh/access token stored in localStorage/sessionStorage — tokens accessible to any same-origin JavaScript including XSS payloads (prefer httpOnly cookies).",
            ))

        if _TR_TOKEN_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "token_refresh_exfil", "FAIL",
                detail="Refresh token transmitted via fetch/sendBeacon — refresh token forwarded to remote endpoint enabling persistent account takeover.",
            ))

        if _TR_LOGGED_RE.search(body):
            findings.append(self._result(
                url, "token_refresh_logged", "WARN",
                detail="Refresh/access token logged to console — tokens visible to browser extensions and developer tools (token exposure via logging).",
            ))

        return findings or [self._result(url, "token_refresh_safe", "PASS")]
