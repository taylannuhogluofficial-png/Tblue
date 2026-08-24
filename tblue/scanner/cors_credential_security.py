"""CORS Credential security scanner — passive detection of CORS misuse with credentials."""
import re
from .base import BaseScanner

_CC_ANY_RE = re.compile(
    r'(?:credentials\s*:\s*["\']include["\']|'
    r'withCredentials\s*[=:]\s*true|'
    r'Access-Control-Allow-Credentials\b|'
    r'credentials\s*:\s*["\']same-origin["\']|'
    r'fetch\s*\([^)]{0,100}credentials)',
    re.I,
)

_CC_WILDCARD_WITH_CREDS_RE = re.compile(
    r'credentials\s*:\s*["\']include["\'][^;]{0,300}'
    r'["\'][*]["\']',
    re.I,
)

_CC_FROM_PARAM_RE = re.compile(
    r'fetch\s*\([^;]{0,200}'
    r'credentials\s*:\s*["\']include["\'][^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_CC_THIRD_PARTY_WITH_CREDS_RE = re.compile(
    r'fetch\s*\(\s*["\']https?://(?!(?:localhost|127\.0\.0\.1))[^"\']{0,200}["\']'
    r'[^;]{0,300}'
    r'credentials\s*:\s*["\']include["\']',
    re.I,
)

_CC_XHR_WITH_CREDS_RE = re.compile(
    r'withCredentials\s*=\s*true[^;]{0,400}'
    r'(?:third.?party|external|analytics|cdn)',
    re.I,
)


class CORSCredentialSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "cors_credential_not_used", "PASS")]

        body = resp.text

        if not _CC_ANY_RE.search(body):
            return [self._result(url, "cors_credential_not_used", "PASS")]

        findings = []

        if _CC_WILDCARD_WITH_CREDS_RE.search(body):
            findings.append(self._result(
                url, "cors_credentials_with_wildcard", "FAIL",
                detail="credentials:'include' used with wildcard origin '*' — browsers block this combination, but code pattern indicates intent to bypass CORS protections.",
            ))

        if _CC_THIRD_PARTY_WITH_CREDS_RE.search(body):
            findings.append(self._result(
                url, "cors_credentials_to_third_party", "FAIL",
                detail="fetch() to external domain with credentials:'include' — session cookies and auth headers sent cross-origin (CSRF token bypass / session forwarding).",
            ))

        if _CC_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "cors_credential_url_from_param", "WARN",
                detail="fetch() with credentials:'include' to URL from URL parameter — attacker-controlled cross-origin credential request enables CSRF-like attacks.",
            ))

        if _CC_XHR_WITH_CREDS_RE.search(body):
            findings.append(self._result(
                url, "cors_xhr_credentials_to_external", "WARN",
                detail="XHR withCredentials=true to third-party/analytics/CDN — credentials forwarded to external endpoint (unintended session sharing).",
            ))

        return findings or [self._result(url, "cors_credential_safe", "PASS")]
