"""Proxy / Reflect security scanner — passive detection of Proxy trap misuse for surveillance."""
import re
from .base import BaseScanner

_PR_ANY_RE = re.compile(
    r'(?:new\s+Proxy\s*\(|Proxy\b|Reflect\b|Reflect\.get\s*\(|'
    r'Reflect\.set\s*\(|Reflect\.apply\s*\(|Reflect\.construct\s*\(|'
    r'handler\.get\s*=|handler\.set\s*=|handler\.apply\s*=|'
    r'handler\.construct\s*=|handler\.has\s*=|handler\.deleteProperty\s*=)',
    re.I,
)

_PR_EXFIL_ON_GET_RE = re.compile(
    r'handler\.get\s*=[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_PR_EXFIL_ON_SET_RE = re.compile(
    r'handler\.set\s*=[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_PR_SENSITIVE_PROXY_TARGET_RE = re.compile(
    r'new\s+Proxy\s*\([^;]{0,300}'
    r'(?:password|token|credential|auth|secret|document\.cookie)',
    re.I,
)

_PR_FROM_PARAM_RE = re.compile(
    r'new\s+Proxy\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class ProxyReflectSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "proxy_reflect_not_used", "PASS")]

        body = resp.text

        if not _PR_ANY_RE.search(body):
            return [self._result(url, "proxy_reflect_not_used", "PASS")]

        findings = []

        if _PR_EXFIL_ON_GET_RE.search(body):
            findings.append(self._result(
                url, "proxy_get_trap_exfil", "WARN",
                detail="Proxy handler.get trap transmits data via fetch/sendBeacon — property read operations exfiltrated via Proxy get trap.",
            ))

        if _PR_EXFIL_ON_SET_RE.search(body):
            findings.append(self._result(
                url, "proxy_set_trap_exfil", "FAIL",
                detail="Proxy handler.set trap transmits data via fetch/sendBeacon — property write values exfiltrated; classic keylogger pattern via object property assignment.",
            ))

        if _PR_SENSITIVE_PROXY_TARGET_RE.search(body):
            findings.append(self._result(
                url, "proxy_wraps_sensitive_object", "WARN",
                detail="new Proxy() wraps password/token/credential/cookie object — sensitive data object wrapped to intercept all accesses.",
            ))

        if _PR_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "proxy_target_from_param", "WARN",
                detail="new Proxy() target sourced from URL parameter — attacker-controlled proxy target enables arbitrary object interception.",
            ))

        return findings or [self._result(url, "proxy_reflect_safe", "PASS")]
