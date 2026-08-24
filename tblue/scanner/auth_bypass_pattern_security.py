"""Auth Bypass Pattern security scanner — passive detection of authentication bypass patterns."""
import re
from .base import BaseScanner

_ABP_ANY_RE = re.compile(
    r'(?:isAuthenticated\b|isLoggedIn\b|isAdmin\b|'
    r'hasPermission\b|checkAuth\b|verifyToken\b|'
    r'auth\.required\b|requireAuth\b)',
    re.I,
)

_ABP_ROLE_FROM_PARAM_RE = re.compile(
    r'(?:isAdmin|isAuthenticated|role|permission)\b[^;]{0,300}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_ABP_CLIENT_SIDE_ONLY_RE = re.compile(
    r'(?:isAdmin|isAuthenticated|hasPermission)\s*=[^;]{0,200}'
    r'(?:localStorage|sessionStorage|cookie|JSON\.parse)',
    re.I,
)

_ABP_BOOLEAN_SHORT_CIRCUIT_RE = re.compile(
    r'(?:isAdmin|isAuthenticated)\s*\|\|\s*(?:true\b|1\b|["\']1["\'])',
    re.I,
)

_ABP_HARDCODED_BYPASS_RE = re.compile(
    r'(?:password|secret|apiKey|token)\s*===?\s*["\'][a-zA-Z0-9]{1,20}["\']',
    re.I,
)


class AuthBypassPatternSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "auth_bypass_not_used", "PASS")]

        body = resp.text

        if not _ABP_ANY_RE.search(body):
            return [self._result(url, "auth_bypass_not_used", "PASS")]

        findings = []

        if _ABP_ROLE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "auth_bypass_role_from_param", "FAIL",
                detail="isAdmin/isAuthenticated/role value read from URL parameter — authorization decision from attacker-controlled URL parameter (client-side auth bypass).",
            ))

        if _ABP_CLIENT_SIDE_ONLY_RE.search(body):
            findings.append(self._result(
                url, "auth_bypass_client_side_only", "FAIL",
                detail="isAdmin/isAuthenticated/hasPermission set from localStorage/sessionStorage/cookie — authentication state from client-controlled storage is bypassable (client-side only auth).",
            ))

        if _ABP_BOOLEAN_SHORT_CIRCUIT_RE.search(body):
            findings.append(self._result(
                url, "auth_bypass_boolean_short_circuit", "FAIL",
                detail="isAdmin || true or isAuthenticated || 1 — always-true boolean short-circuit in auth check completely bypasses authentication requirement.",
            ))

        if _ABP_HARDCODED_BYPASS_RE.search(body):
            findings.append(self._result(
                url, "auth_bypass_hardcoded_credential", "FAIL",
                detail="password/secret/apiKey/token compared to short hardcoded string — hardcoded credential check enables trivial authentication bypass if string is known.",
            ))

        return findings or [self._result(url, "auth_bypass_safe", "PASS")]
