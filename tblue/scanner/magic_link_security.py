"""Magic Link security scanner — passive detection of token-based auth link misuse."""
import re
from .base import BaseScanner

_ML_ANY_RE = re.compile(
    r'(?:magic.?link|magic.?token|passwordless|'
    r'email.?token|sign.?in.?link|login.?link|'
    r'verification.?token|email.?verification|'
    r'one.?time.?link)',
    re.I,
)

_ML_TOKEN_FROM_PARAM_RE = re.compile(
    r'(?:magic.?token|verification.?token|sign.?in.?link)\b[^;]{0,300}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_ML_TOKEN_LOGGED_RE = re.compile(
    r'(?:magic.?link|magic.?token|email.?token)\b[^;]{0,400}'
    r'(?:console\.log|console\.error|console\.warn)',
    re.I,
)

_ML_TOKEN_EXFIL_RE = re.compile(
    r'(?:magic.?token|verification.?token|email.?token)\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_ML_SHORT_TOKEN_RE = re.compile(
    r'(?:magic.?token|login.?token)\s*=\s*["\'][a-zA-Z0-9]{1,12}["\']',
    re.I,
)


class MagicLinkSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "magic_link_not_used", "PASS")]

        body = resp.text

        if not _ML_ANY_RE.search(body):
            return [self._result(url, "magic_link_not_used", "PASS")]

        findings = []

        if _ML_TOKEN_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "magic_link_token_from_param", "WARN",
                detail="Magic link/verification token read from URL parameter without apparent validation — ensure token is verified server-side before authentication.",
            ))

        if _ML_TOKEN_LOGGED_RE.search(body):
            findings.append(self._result(
                url, "magic_link_token_logged", "FAIL",
                detail="Magic link/email token passed to console.log/error — authentication tokens logged to browser console, visible to any page JS or browser extension.",
            ))

        if _ML_TOKEN_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "magic_link_token_exfil", "FAIL",
                detail="Magic/verification token transmitted via fetch/sendBeacon to non-auth endpoint — authentication token forwarded to analytics or third-party server.",
            ))

        if _ML_SHORT_TOKEN_RE.search(body):
            findings.append(self._result(
                url, "magic_link_short_token", "WARN",
                detail="Magic link/login token appears to be a short string (≤12 chars) — short tokens are guessable; authentication tokens must be cryptographically random and ≥128 bits.",
            ))

        return findings or [self._result(url, "magic_link_safe", "PASS")]
