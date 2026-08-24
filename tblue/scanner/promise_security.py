"""Promise security scanner — passive detection of Promise misuse for sensitive data exfiltration."""
import re
from .base import BaseScanner

_PS_ANY_RE = re.compile(
    r'(?:new\s+Promise\s*\(|Promise\.resolve\s*\(|Promise\.reject\s*\(|'
    r'Promise\.all\s*\(|Promise\.allSettled\s*\(|Promise\.race\s*\(|'
    r'Promise\.any\s*\(|\.then\s*\(|\.catch\s*\(|\.finally\s*\(|'
    r'async\s+function\b|await\s+|unhandledrejection\b)',
    re.I,
)

_PS_CREDENTIALS_IN_PROMISE_RE = re.compile(
    r'(?:new\s+Promise|Promise\.resolve)\s*\([^;]{0,300}'
    r'(?:password|token|secret|auth|credential)',
    re.I,
)

_PS_EXFIL_IN_THEN_RE = re.compile(
    r'\.then\s*\([^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)[^;]{0,200}'
    r'(?:password|token|secret|auth|credential|e\.detail)',
    re.I,
)

_PS_UNHANDLED_REJECTION_EXFIL_RE = re.compile(
    r'unhandledrejection\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_PS_FROM_PARAM_RE = re.compile(
    r'(?:new\s+Promise|Promise\.resolve)\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class PromiseSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "promise_not_used", "PASS")]

        body = resp.text

        if not _PS_ANY_RE.search(body):
            return [self._result(url, "promise_not_used", "PASS")]

        findings = []

        if _PS_CREDENTIALS_IN_PROMISE_RE.search(body):
            findings.append(self._result(
                url, "promise_credentials_in_resolve", "WARN",
                detail="Promise.resolve()/new Promise() resolves with password/token/credential — sensitive data propagated through promise chain.",
            ))

        if _PS_EXFIL_IN_THEN_RE.search(body):
            findings.append(self._result(
                url, "promise_exfil_in_then", "FAIL",
                detail=".then() handler transmits password/token/credential via fetch/sendBeacon — promise resolution triggers credential exfiltration.",
            ))

        if _PS_UNHANDLED_REJECTION_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "promise_unhandled_rejection_exfil", "WARN",
                detail="unhandledrejection event transmitted to remote — promise rejection reasons including error messages and stack traces exfiltrated.",
            ))

        if _PS_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "promise_from_url_param", "WARN",
                detail="Promise created/resolved with URL parameter value — attacker-controlled promise resolution value.",
            ))

        return findings or [self._result(url, "promise_safe", "PASS")]
