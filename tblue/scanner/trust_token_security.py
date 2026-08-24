"""Private State Tokens (formerly Trust Tokens) security scanner — passive detection of token misuse."""
import re
from .base import BaseScanner

_TT_ANY_RE = re.compile(
    r'(?:privateToken\b|trustToken\b|Sec-Private-State-Token\b|Sec-Trust-Token\b|'
    r'hasPrivateToken\s*\(|hasTrustToken\s*\(|Private-State-Token\b)',
    re.I,
)

_TT_TOKEN_EXFIL_RE = re.compile(
    r'(?:privateToken|trustToken)[^;]{0,200}(?:send|redemption|redeem)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_TT_ISSUER_FROM_PARAM_RE = re.compile(
    r'(?:privateToken|trustToken)[^;]{0,200}'
    r'(?:issuer|issuers)[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_TT_TRACKING_CORRELATION_RE = re.compile(
    r'(?:hasPrivateToken|hasTrustToken)\s*\([^;]{0,200}(?:fetch|sendBeacon|analytics)',
    re.I,
)

_TT_FORCED_REDEMPTION_RE = re.compile(
    r'(?:DOMContentLoaded|pageshow)[^;]{0,300}'
    r'(?:privateToken|trustToken)[^;]{0,200}(?:redemption|redeem)',
    re.I,
)


class TrustTokenSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "trust_token_not_used", "PASS")]

        body = resp.text
        headers_str = " ".join(f"{k}: {v}" for k, v in (resp.headers or {}).items())
        combined = body + "\n" + headers_str

        if not _TT_ANY_RE.search(combined):
            return [self._result(url, "trust_token_not_used", "PASS")]

        findings = []

        if _TT_TOKEN_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "trust_token_redemption_exfiltrated", "FAIL",
                detail="Private State Token redemption result transmitted to remote — token-based user tracking/correlation.",
            ))

        if _TT_ISSUER_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "trust_token_issuer_from_param", "FAIL",
                detail="Trust Token issuer set from URL parameter — attacker-controlled token issuer manipulation.",
            ))

        if _TT_TRACKING_CORRELATION_RE.search(body):
            findings.append(self._result(
                url, "trust_token_presence_tracking", "WARN",
                detail="hasPrivateToken() result transmitted to analytics — token presence used for cross-site tracking.",
            ))

        if _TT_FORCED_REDEMPTION_RE.search(body):
            findings.append(self._result(
                url, "trust_token_forced_redemption_on_load", "WARN",
                detail="Trust Token redemption triggered on page load — automatic token consumption without user action.",
            ))

        return findings or [self._result(url, "trust_token_safe", "PASS")]
