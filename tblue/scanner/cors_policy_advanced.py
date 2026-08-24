"""CORS Policy Advanced scanner — passive detection of dangerous CORS header configurations."""
import re
from .base import BaseScanner

_CORS_ANY_RE = re.compile(
    r'(?:access-control-allow-origin|access-control-allow-credentials|'
    r'access-control-allow-methods|access-control-allow-headers)',
    re.I,
)

_CORS_WILDCARD_WITH_CREDS_RE = re.compile(
    r'access-control-allow-origin\s*:\s*\*',
    re.I,
)

_CORS_CREDS_TRUE_RE = re.compile(
    r'access-control-allow-credentials\s*:\s*true',
    re.I,
)

_CORS_NULL_ORIGIN_RE = re.compile(
    r'access-control-allow-origin\s*:\s*null\b',
    re.I,
)

_CORS_REFLECT_ORIGIN_RE = re.compile(
    r'access-control-allow-origin\s*:\s*https?://[^\s,]+',
    re.I,
)

_CORS_ALLOW_ALL_METHODS_RE = re.compile(
    r'access-control-allow-methods\s*:[^\r\n]*\bDELETE\b[^\r\n]*\bPUT\b|'
    r'access-control-allow-methods\s*:[^\r\n]*\bPUT\b[^\r\n]*\bDELETE\b',
    re.I,
)

_CORS_ALLOW_SENSITIVE_HEADERS_RE = re.compile(
    r'access-control-allow-headers\s*:[^\r\n]*'
    r'(?:authorization|x-api-key|x-auth-token)',
    re.I,
)


class CORSPolicyAdvancedScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "cors_policy_advanced_not_used", "PASS")]

        headers_str = ' '.join(f'{k}: {v}' for k, v in resp.headers.items())

        if not _CORS_ANY_RE.search(headers_str):
            return [self._result(url, "cors_policy_advanced_not_used", "PASS")]

        findings = []
        has_wildcard = bool(_CORS_WILDCARD_WITH_CREDS_RE.search(headers_str))
        has_creds = bool(_CORS_CREDS_TRUE_RE.search(headers_str))

        if has_wildcard and has_creds:
            findings.append(self._result(
                url, "cors_wildcard_with_credentials", "FAIL",
                detail="Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true — browsers block this combination per spec but misconfigured clients/libraries may still send credentials to any origin.",
            ))

        if _CORS_NULL_ORIGIN_RE.search(headers_str):
            findings.append(self._result(
                url, "cors_null_origin_allowed", "FAIL",
                detail="Access-Control-Allow-Origin: null — sandbox iframes and local file:// pages send Origin: null; allowing it lets attacker-controlled sandboxed pages make credentialed cross-origin requests.",
            ))

        if _CORS_REFLECT_ORIGIN_RE.search(headers_str) and has_creds:
            findings.append(self._result(
                url, "cors_origin_reflection_with_credentials", "FAIL",
                detail="Server reflects a specific origin in ACAO with credentials enabled — if reflection logic trusts attacker.com, full cross-origin credentialed access is granted; classic CORS misconfiguration.",
            ))

        if _CORS_ALLOW_ALL_METHODS_RE.search(headers_str):
            findings.append(self._result(
                url, "cors_allow_destructive_methods", "WARN",
                detail="Access-Control-Allow-Methods includes both PUT and DELETE — cross-origin requests can modify and delete resources; restrict to safe methods (GET, POST) unless cross-origin writes are intentional.",
            ))

        if _CORS_ALLOW_SENSITIVE_HEADERS_RE.search(headers_str):
            findings.append(self._result(
                url, "cors_expose_sensitive_request_headers", "WARN",
                detail="Access-Control-Allow-Headers exposes Authorization, X-Api-Key, or X-Auth-Token — cross-origin scripts can read or set these headers, enabling credential theft or injection.",
            ))

        return findings or [self._result(url, "cors_policy_advanced_safe", "PASS")]
