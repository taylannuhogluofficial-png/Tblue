"""Storage Event security scanner — passive detection of storage event misuse for cross-tab surveillance."""
import re
from .base import BaseScanner

_SE_ANY_RE = re.compile(
    r'(?:storage\b|localStorage\b|sessionStorage\b|'
    r'addEventListener\s*\(\s*["\']storage["\']|'
    r'StorageEvent\b|window\.onstorage\b|'
    r'localStorage\.setItem\s*\(|localStorage\.getItem\s*\(|'
    r'sessionStorage\.setItem\s*\(|sessionStorage\.getItem\s*\()',
    re.I,
)

_SE_STORAGE_EXFIL_RE = re.compile(
    r'(?:localStorage|sessionStorage)\.getItem\s*\([^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_SE_SENSITIVE_STORAGE_WRITE_RE = re.compile(
    r'(?:localStorage|sessionStorage)\.setItem\s*\([^;]{0,300}'
    r'(?:password|token|secret|auth|credential|ssn|credit)',
    re.I,
)

_SE_STORAGE_EVENT_EXFIL_RE = re.compile(
    r'addEventListener\s*\(\s*["\']storage["\'][^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_SE_STORAGE_FROM_PARAM_RE = re.compile(
    r'(?:localStorage|sessionStorage)\.setItem\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class StorageEventSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "storage_event_not_used", "PASS")]

        body = resp.text

        if not _SE_ANY_RE.search(body):
            return [self._result(url, "storage_event_not_used", "PASS")]

        findings = []

        if _SE_STORAGE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "storage_event_getitem_exfil", "FAIL",
                detail="localStorage/sessionStorage.getItem() result transmitted via fetch/sendBeacon — stored data exfiltrated to remote endpoint.",
            ))

        if _SE_SENSITIVE_STORAGE_WRITE_RE.search(body):
            findings.append(self._result(
                url, "storage_event_sensitive_data_stored", "WARN",
                detail="localStorage/sessionStorage.setItem() stores password/token/credential — sensitive data persisted in unencrypted browser storage.",
            ))

        if _SE_STORAGE_EVENT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "storage_event_cross_tab_exfil", "WARN",
                detail="storage event listener transmits data to remote — cross-tab storage changes exfiltrated via storage event surveillance.",
            ))

        if _SE_STORAGE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "storage_event_write_from_param", "WARN",
                detail="localStorage/sessionStorage.setItem() value sourced from URL parameter — attacker-controlled data written to persistent browser storage.",
            ))

        return findings or [self._result(url, "storage_event_safe", "PASS")]
