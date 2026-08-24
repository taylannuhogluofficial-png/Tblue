"""SameSite Cookie security scanner — passive detection of CSRF-vulnerable cookie configuration."""
import re
from .base import BaseScanner

_SSC_ANY_RE = re.compile(
    r'(?:document\.cookie\s*=|SameSite\s*=|samesite\s*=|'
    r'Secure\s*;|HttpOnly\s*;|Set-Cookie\b|'
    r'\.cookie\s*=)',
    re.I,
)

_SSC_NONE_WITHOUT_SECURE_RE = re.compile(
    r'SameSite\s*=\s*["\']?None["\']?[^;]{0,300}'
    r'(?!.*Secure)',
    re.I,
)

_SSC_LAX_ON_AUTH_RE = re.compile(
    r'(?:session|auth|token|login).{0,200}'
    r'SameSite\s*=\s*["\']?Lax',
    re.I,
)

_SSC_NO_SAMESITE_RE = re.compile(
    r'document\.cookie\s*=[^;]{0,300}'
    r'(?:session|auth|token|JSESSIONID)[^;]{0,100}'
    r'(?!SameSite)',
    re.I,
)

_SSC_COOKIE_FROM_PARAM_RE = re.compile(
    r'document\.cookie\s*=[^;]{0,300}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class SameSiteCookieSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "same_site_cookie_not_used", "PASS")]

        body = resp.text

        if not _SSC_ANY_RE.search(body):
            return [self._result(url, "same_site_cookie_not_used", "PASS")]

        findings = []

        if _SSC_NONE_WITHOUT_SECURE_RE.search(body):
            findings.append(self._result(
                url, "same_site_none_without_secure", "FAIL",
                detail="SameSite=None without Secure flag — SameSite=None cookies must have Secure flag; browsers reject them otherwise, and plain HTTP transmission is insecure.",
            ))

        if _SSC_LAX_ON_AUTH_RE.search(body):
            findings.append(self._result(
                url, "same_site_lax_on_auth_cookie", "WARN",
                detail="SameSite=Lax on session/auth/token cookie — Lax allows top-level cross-site GET requests to include cookie (CSRF risk for GET-based state changes).",
            ))

        if _SSC_COOKIE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "same_site_cookie_from_param", "FAIL",
                detail="document.cookie set from URL parameter — cookie value injected from URL enables cookie injection / session fixation attacks.",
            ))

        if _SSC_NO_SAMESITE_RE.search(body):
            findings.append(self._result(
                url, "same_site_missing_on_session_cookie", "WARN",
                detail="Session/auth/token cookie set via document.cookie without SameSite attribute — missing SameSite defaults to Lax but should be explicit Strict for session cookies.",
            ))

        return findings or [self._result(url, "same_site_cookie_safe", "PASS")]
