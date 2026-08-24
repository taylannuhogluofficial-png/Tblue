"""JWT Advanced security scanner — deeper JWT validation pattern detection."""
import re
from .base import BaseScanner

_JWA_ANY_RE = re.compile(
    r'(?:jwt\b|JSON\.parse\s*\(\s*atob\s*\(|'
    r'\.split\s*\(\s*["\'][.]["\'](?:\s*\[1\]|\s*\[0\])|'
    r'Bearer\s+|Authorization\s*:|'
    r'verify(?:Token|Jwt|Signature)\b|decodeJwt\b)',
    re.I,
)

_JWA_NONE_ALG_RE = re.compile(
    r'(?:alg\s*:\s*["\']none["\']|"alg"\s*:\s*"none"|'
    r'algorithm\s*:\s*["\']none["\'])',
    re.I,
)

_JWA_FROM_PARAM_RE = re.compile(
    r'(?:jwt|token|bearer)\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_JWA_PAYLOAD_LOGGED_RE = re.compile(
    r'(?:JSON\.parse\s*\(\s*atob|decodeJwt)\b[^;]{0,300}'
    r'(?:console\.log|console\.warn|console\.error)',
    re.I,
)

_JWA_PAYLOAD_EXFIL_RE = re.compile(
    r'(?:JSON\.parse\s*\(\s*atob|decodeJwt)\b[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_JWA_WEAK_SECRET_RE = re.compile(
    r'(?:jwt|sign|verify)\b[^;]{0,300}'
    r'(?:secret\s*:\s*["\'][a-zA-Z0-9]{1,20}["\']|'
    r'["\'](?:secret|password|123456|qwerty)["\'])',
    re.I,
)


class JwtAdvancedSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "jwt_advanced_not_used", "PASS")]

        body = resp.text

        if not _JWA_ANY_RE.search(body):
            return [self._result(url, "jwt_advanced_not_used", "PASS")]

        findings = []

        if _JWA_NONE_ALG_RE.search(body):
            findings.append(self._result(
                url, "jwt_none_algorithm", "FAIL",
                detail="JWT with alg:none detected — the 'none' algorithm disables signature verification; any unsigned JWT would be accepted (critical authentication bypass).",
            ))

        if _JWA_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "jwt_token_from_param", "WARN",
                detail="JWT/Bearer token read from URL parameter — tokens in URLs are logged in server access logs, browser history, and Referer headers (token leakage).",
            ))

        if _JWA_PAYLOAD_LOGGED_RE.search(body):
            findings.append(self._result(
                url, "jwt_payload_logged", "WARN",
                detail="Decoded JWT payload logged to console — JWT claims (user ID, roles, expiry) visible to browser extensions and devtools (information disclosure).",
            ))

        if _JWA_PAYLOAD_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "jwt_payload_exfil", "FAIL",
                detail="Decoded JWT payload transmitted via fetch/sendBeacon — JWT claims (user ID, roles, email) exfiltrated to remote endpoint.",
            ))

        if _JWA_WEAK_SECRET_RE.search(body):
            findings.append(self._result(
                url, "jwt_weak_secret", "FAIL",
                detail="JWT signing/verification uses short or common secret string — weak JWT secret enables offline brute-force to forge valid tokens.",
            ))

        return findings or [self._result(url, "jwt_advanced_safe", "PASS")]
