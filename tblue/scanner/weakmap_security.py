"""WeakMap / WeakSet / WeakRef security scanner — passive detection of WeakMap misuse."""
import re
from .base import BaseScanner

_WM_ANY_RE = re.compile(
    r'(?:new\s+WeakMap\s*\(|new\s+WeakSet\s*\(|new\s+WeakRef\s*\(|'
    r'WeakMap\b|WeakSet\b|WeakRef\b|FinalizationRegistry\b|'
    r'weakMap\.set\s*\(|weakMap\.get\s*\(|weakMap\.has\s*\(|'
    r'weakRef\.deref\s*\()',
    re.I,
)

_WM_SENSITIVE_STORE_RE = re.compile(
    r'weakMap\.set\s*\([^;]{0,300}'
    r'(?:password|token|secret|auth|credential|cookie)',
    re.I,
)

_WM_EXFIL_ON_DEREF_RE = re.compile(
    r'weakRef\.deref\s*\([^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_WM_FINALIZATION_EXFIL_RE = re.compile(
    r'FinalizationRegistry\b[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_WM_FROM_PARAM_RE = re.compile(
    r'new\s+WeakMap\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class WeakMapSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "weakmap_not_used", "PASS")]

        body = resp.text

        if not _WM_ANY_RE.search(body):
            return [self._result(url, "weakmap_not_used", "PASS")]

        findings = []

        if _WM_SENSITIVE_STORE_RE.search(body):
            findings.append(self._result(
                url, "weakmap_stores_sensitive_data", "WARN",
                detail="WeakMap.set() stores password/token/credential values — sensitive data cached in WeakMap keyed to DOM elements.",
            ))

        if _WM_EXFIL_ON_DEREF_RE.search(body):
            findings.append(self._result(
                url, "weakmap_deref_exfil", "WARN",
                detail="WeakRef.deref() result transmitted via fetch/sendBeacon — dereferenced WeakRef value exfiltrated to remote endpoint.",
            ))

        if _WM_FINALIZATION_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "weakmap_finalization_registry_exfil", "WARN",
                detail="FinalizationRegistry callback transmits data to remote — GC finalization callbacks used to exfiltrate object lifecycle data.",
            ))

        if _WM_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "weakmap_from_param", "WARN",
                detail="new WeakMap() initialized from URL parameter — attacker-controlled WeakMap initial entries.",
            ))

        return findings or [self._result(url, "weakmap_safe", "PASS")]
